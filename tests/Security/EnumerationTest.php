<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Identical status, body and `code` for known, unknown, disabled, unverified and locked
 * accounts on every guest endpoint that names an account; mail only for the real,
 * active one.
 */
beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['verification.mode' => 'required_for_login', 'throttle.email_request.max' => 100, 'throttle.email_request_account.max' => 100, 'throttle.login.max' => 100]);
});

dataset('accounts', [
    'known' => [fn (): string => User::factory()->create()->email],
    'unknown' => [fn (): string => 'ghost@example.com'],
    'disabled' => [fn (): string => User::factory()->disabled()->create()->email],
    'unverified' => [fn (): string => User::factory()->unverified()->create()->email],
]);

dataset('endpoints', [
    'password login (wrong password)' => ['/users/auth/login', fn (string $email): array => ['identifier' => $email, 'password' => 'wrong-password']],
    'magic link request' => ['/users/auth/login/magic-link', fn (string $email): array => ['email' => $email]],
    'email code request' => ['/users/auth/login/otp', fn (string $email): array => ['email' => $email]],
    'email code verify' => ['/users/auth/login/otp/verify', fn (string $email): array => ['email' => $email, 'code' => '000000']],
    'forgot password' => ['/users/auth/password/forgot', fn (string $email): array => ['email' => $email]],
    'verification resend' => ['/users/auth/email/verification/resend', fn (string $email): array => ['email' => $email]],
    'registration' => ['/users/auth/register', fn (string $email): array => ['email' => $email, 'password' => 'a-long-enough-passphrase']],
]);

it('answers every account state identically', function (string $uri, Closure $payload): void {
    $responses = [];

    $states = [
        'known' => User::factory()->create()->email,
        'unknown' => 'ghost@example.com',
        'disabled' => User::factory()->disabled()->create()->email,
        'unverified' => User::factory()->unverified()->create()->email,
        'locked' => User::factory()->create(['locked_until' => now()->addHour()])->email,
    ];

    foreach ($states as $state => $email) {
        $response = $this->postJson($uri, $payload($email));
        $responses[$state] = [$response->status(), $response->json()];
    }

    expect(array_unique(array_map('serialize', $responses)))->toHaveCount(1);
})->with('endpoints');

it('answers invitation previews uniformly', function (): void {
    $this->postJson('/users/auth/invitations/preview', ['token' => 'nope'])->assertStatus(422)->assertJsonPath('code', 'invalid_invitation');
    $this->postJson('/users/auth/invitations/accept', ['token' => 'nope', 'password' => 'a-long-enough-passphrase'])->assertStatus(422)->assertJsonPath('code', 'invalid_invitation');
});

it('never offers credentials in passwordless options', function (): void {
    $this->postJson('/users/auth/login/passkey/options')->assertOk()->assertJsonPath('publicKey.allowCredentials', []);
});

it('mails only the real active account', function (Closure $email): void {
    $address = $email();

    $this->postJson('/users/auth/login/magic-link', ['email' => $address])->assertStatus(202);

    $user = User::query()->where('email', $address)->first();

    if ($user !== null && ! $user->isDisabled()) {
        Notification::assertSentTo($user, MagicLinkNotification::class);
    } else {
        Notification::assertNothingSent();
    }
})->with('accounts');
