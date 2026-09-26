<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Challenges\StartTwoFactorEnrolmentStep;
use RoundlyConsulting\Auth\Contracts\RendersQrCode;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Events\RecoveryCodeUsed;
use RoundlyConsulting\Auth\Events\TwoFactorEnabled;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\RecoveryCodeUsedNotification;
use RoundlyConsulting\Auth\Notifications\TwoFactorEnabledNotification;
use RoundlyConsulting\Auth\Support\QrCodeRenderer;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Jwt\Facades\Jwt;

function loginForChallenge(User $user): string
{
    return test()->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'challenge')
        ->json('challenge_token');
}

beforeEach(function (): void {
    Notification::fake();
    $this->user = User::factory()->create();
});

it('completes a totp challenge over http with amr pwd, otp, mfa', function (): void {
    $secret = enableTotp($this->user);
    $token = loginForChallenge($this->user);

    $response = $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => totpCode($secret)], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    $claims = Jwt::verify($response->json('access_token'), 'app-users');

    expect($claims->authMethods())->toBe(['pwd', 'otp', 'mfa']);
});

it('counts a wrong code and reports the attempts left', function (): void {
    enableTotp($this->user);
    $token = loginForChallenge($this->user);

    $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => '000000'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_failed')
        ->assertJsonPath('attempts_left', 4);
});

it('accepts a recovery code on the same endpoint and tells the owner how many remain', function (): void {
    Event::fake([RecoveryCodeUsed::class]);
    enableTotp($this->user);
    $token = loginForChallenge($this->user);

    $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => recoveryCodes()[0]], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    Event::assertDispatched(RecoveryCodeUsed::class, fn (RecoveryCodeUsed $event): bool => $event->remaining === 2);
    Notification::assertSentTo($this->user, RecoveryCodeUsedNotification::class, fn ($notification): bool => $notification->data->replacements['remaining'] === 2);
});

it('rejects the same totp code the second time, across logins', function (): void {
    $secret = enableTotp($this->user);
    $code = totpCode($secret);

    $first = loginForChallenge($this->user);
    $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $first, 'code' => $code], ['User-Agent' => 'PestBrowser/1.0'])->assertOk();

    $second = loginForChallenge($this->user);
    $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $second, 'code' => $code], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_failed');
});

it('maps the two-factor limiter to 429 with Retry-After', function (): void {
    config()->set('two-factor.attempts.max', 2);
    $this->configureGuard('users', ['challenge.max_attempts' => 10]);
    enableTotp($this->user);
    $token = loginForChallenge($this->user);

    foreach (range(1, 2) as $attempt) {
        $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => '000000'], ['User-Agent' => 'PestBrowser/1.0'])->assertStatus(422);
    }

    $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => '000000'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(429)
        ->assertHeader('Retry-After');
});

it('refuses a totp code for a passkey-only step', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required_when_enrolled']);
    addPasskey($this->user);
    $token = loginForChallenge($this->user);

    $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => '123456'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_not_allowed');
});

it('forces totp enrolment inside the challenge, with a qr code, and completes the login', function (): void {
    Event::fake([TwoFactorEnabled::class]);
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'two_factor.issuer' => 'Users App']);
    $old = issuePair($this->user);
    $token = loginForChallenge($this->user);

    $setup = $this->postJson('/users/auth/challenge/two-factor/enrol', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJsonStructure(['secret', 'provisioning_uri', 'qr_svg', 'recovery_codes', 'issuer'])
        ->json();

    expect($setup['qr_svg'])->toStartWith('<svg')->and($setup['provisioning_uri'])->toContain('issuer=Users%20App');

    $response = $this->postJson('/users/auth/challenge/two-factor/enrol/confirm', ['challenge_token' => $token, 'code' => totpCode($setup['secret'])], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect(Jwt::verify($response->json('access_token'), 'app-users')->authMethods())->toBe(['pwd', 'otp', 'mfa'])
        ->and($this->user->fresh()?->hasTwoFactorEnabled())->toBeTrue();

    $this->getJson('/users/auth/me', bearer($old))->assertUnauthorized();
    $this->getJson('/users/auth/me', ['Authorization' => 'Bearer '.$response->json('access_token')])->assertOk();
    Event::assertDispatched(TwoFactorEnabled::class);
    Notification::assertSentTo($this->user, TwoFactorEnabledNotification::class);
});

it('counts a wrong enrolment confirmation code', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $token = loginForChallenge($this->user);
    Authentication::guard('users');

    $this->postJson('/users/auth/challenge/two-factor/enrol', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])->assertOk();

    expect(fn () => Authentication::guard('users')->completeChallenge(new ChallengeFactorData($token, FactorMethod::TotpEnrolment, sessionContext(), code: '000000')))
        ->toThrow(ChallengeFactorFailed::class);
});

it('returns the setup without a qr code when rendering fails or is off', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    app()->instance(RendersQrCode::class, new class implements RendersQrCode
    {
        public function otpauthSvg(string $provisioningUri, int $size): ?string
        {
            return null;
        }
    });
    $token = loginForChallenge($this->user);

    $this->postJson('/users/auth/challenge/two-factor/enrol', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('qr_svg', null);
});

it('never lets the qr adapter block an enrolment', function (): void {
    expect((new QrCodeRenderer)->otpauthSvg('not-an-otpauth-uri', 240))->toBeNull()
        ->and((new QrCodeRenderer)->otpauthSvg('otpauth://totp/App:ada%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=App', 200))->toStartWith('<svg');
});

it('walks a challenge through the guard context', function (): void {
    $secret = enableTotp($this->user);
    $pending = Authentication::guard('users')->attempt(new PasswordCredentials($this->user->email, 'correct-horse-battery'), sessionContext())->challenge;

    $result = Authentication::guard('users')->completeChallenge(new ChallengeFactorData($pending->token, FactorMethod::Totp, sessionContext(), code: totpCode($secret)));

    expect($result->isAuthenticated())->toBeTrue();
});

it('keeps a two-step challenge pending after the first step', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required', 'two_factor.passkey_satisfies_required' => false, 'challenge.max_attempts' => 5]);
    $secret = enableTotp($this->user);
    addPasskey($this->user);
    CarbonImmutable::setTestNow(CarbonImmutable::now());

    $pending = Authentication::guard('users')->attempt(new PasswordCredentials($this->user->email, 'correct-horse-battery'), sessionContext())->challenge;
    expect(array_map(fn ($r) => $r->step->value, $pending->remaining))->toBe(['passkey', 'second_factor']);

    CarbonImmutable::setTestNow();
});

it('guards the forced totp enrolment step', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'challenge.enrolment_requires_verified_email' => false]);
    $user = User::factory()->unverified()->create();
    $pending = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->challenge;

    $this->configureGuard('users', ['challenge.enrolment_requires_verified_email' => true]);
    expect(fn () => app(StartTwoFactorEnrolmentStep::class)->execute('users', $pending->token, sessionContext()))
        ->toThrow(EnrolmentRequired::class);

    $this->configureGuard('users', ['challenge.enrolment_requires_verified_email' => false]);
    enableTotp($user);
    expect(fn () => app(StartTwoFactorEnrolmentStep::class)->execute('users', $pending->token, sessionContext()))
        ->toThrow(ChallengeInvalid::class);
});
