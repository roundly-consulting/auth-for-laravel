<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

function requestCode(User $user): string
{
    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext());

    return (string) sentNotification($user, EmailOtpNotification::class)->data->code;
}

it('mails a six-digit code and signs in with it', function (): void {
    $user = User::factory()->create();

    $this->postJson('/users/auth/login/otp', ['email' => $user->email])->assertStatus(202)->assertExactJson(['status' => 'sent']);
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;

    expect($code)->toMatch('/^\d{6}$/');

    $response = $this->postJson('/users/auth/login/otp/verify', ['email' => $user->email, 'code' => $code], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect(claimsOf(new TokenPair($response->json('access_token'), now()->toImmutable(), '', now()->toImmutable(), '', ''))->authMethods())->toBe(['otp']);
});

it('never reveals attempts left on the guest endpoint', function (): void {
    $user = User::factory()->create();
    requestCode($user);

    $known = $this->postJson('/users/auth/login/otp/verify', ['email' => $user->email, 'code' => '000000'])->assertStatus(422)->json();
    $unknown = $this->postJson('/users/auth/login/otp/verify', ['email' => 'ghost@example.com', 'code' => '000000'])->assertStatus(422)->json();

    expect($known)->toBe($unknown)
        ->and($known)->not->toHaveKey('attempts_left')
        ->and($known['code'])->toBe('invalid_code');
});

it('dies after the attempt cap, even for the right code', function (): void {
    $this->configureGuard('users', ['throttle.login.max' => 50]);
    $user = User::factory()->create();
    $code = requestCode($user);

    foreach (range(1, 5) as $attempt) {
        expect(fn () => Authentication::guard('users')->verifyEmailOtp($user->email, $code === '999999' ? '888888' : '999999', sessionContext()))->toThrow(InvalidCode::class);
    }

    expect(fn () => Authentication::guard('users')->verifyEmailOtp($user->email, $code, sessionContext()))->toThrow(InvalidCode::class)
        ->and(OneTimeToken::query()->sole()->invalidated_at)->not->toBeNull();
});

it('binds a code to its address', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $code = requestCode($user);

    expect(fn () => Authentication::guard('users')->verifyEmailOtp($other->email, $code, sessionContext()))->toThrow(InvalidCode::class)
        ->and(Authentication::guard('users')->verifyEmailOtp($user->email, $code, sessionContext())->isAuthenticated())->toBeTrue();
});

it('is single use', function (): void {
    $user = User::factory()->create();
    $code = requestCode($user);

    Authentication::guard('users')->verifyEmailOtp($user->email, $code, sessionContext());

    Authentication::guard('users')->verifyEmailOtp($user->email, $code, sessionContext());
})->throws(InvalidCode::class);

it('is absent when email codes are off', function (): void {
    $this->postJson('/clients/auth/login/otp', ['email' => 'x@example.com'])->assertNotFound();

    $this->configureGuard('users', ['login.email_otp' => false]);
    expect(fn () => Authentication::guard('users')->requestEmailOtp('x@example.com', sessionContext()))->toThrow(LoginMethodDisabled::class)
        ->and(fn () => Authentication::guard('users')->verifyEmailOtp('x@example.com', '123456', sessionContext()))->toThrow(LoginMethodDisabled::class);
});

it('throttles code guesses as login attempts', function (): void {
    $user = User::factory()->create();
    requestCode($user);

    foreach (range(1, 5) as $attempt) {
        $this->postJson('/users/auth/login/otp/verify', ['email' => $user->email, 'code' => '000001'])->assertStatus(422);
    }

    $this->postJson('/users/auth/login/otp/verify', ['email' => $user->email, 'code' => '000001'])->assertStatus(429);
});

it('caps email requests per address across ips', function (): void {
    $this->configureGuard('users', ['throttle.email_request_account.max' => 2]);
    $user = User::factory()->create();

    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext(ip: '1.1.1.1'));
    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext(ip: '1.1.1.2'));

    $this->postJson('/users/auth/login/otp', ['email' => $user->email], ['REMOTE_ADDR' => '1.1.1.3'])->assertStatus(429);
});
