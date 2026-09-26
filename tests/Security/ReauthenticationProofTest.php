<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * An account with a second factor re-proves itself WITH it: a password (or email code)
 * re-authentication does not satisfy a sensitive action gate — including when the factor
 * was enrolled after that proof.
 */
beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['tokens.access_ttl' => 7200]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

/**
 * A session past the fresh-login window that re-authenticated with its password.
 */
function passwordReauthenticatedSession(User $user): TokenPair
{
    $pair = issuePair($user);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    test()->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($pair))->assertOk();

    return $pair;
}

function emailCodeLogin(User $user): TokenPair
{
    test()->postJson('/users/auth/login/otp', ['email' => $user->email])->assertStatus(202);
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;

    $response = test()->postJson('/users/auth/login/otp/verify', ['email' => $user->email, 'code' => $code], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    return new TokenPair((string) $response->json('access_token'), now()->toImmutable(), '', now()->toImmutable(), '', '');
}

it('refuses a password re-authentication made before totp was enabled', function (): void {
    $user = User::factory()->create();
    $pair = passwordReauthenticatedSession($user);
    $secret = enableTotp($user);

    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('code', 'reauthentication_required')
        ->assertJsonPath('methods', ['totp', 'recovery_code']);
    $this->postJson('/users/auth/two-factor/recovery-codes', [], bearer($pair))->assertForbidden();

    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => totpCode($secret)], bearer($pair))->assertOk();
    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))->assertOk();
});

it('refuses a password re-authentication made before a passkey was added', function (): void {
    $this->configureGuard('users', ['invalidation.passkey_changed' => 'none']);
    $user = User::factory()->create();
    $pair = passwordReauthenticatedSession($user);
    $authenticator = registerVirtualPasskey($user);

    $this->postJson('/users/auth/passkeys/options', [], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('methods', ['passkey']);
    $this->deleteJson('/users/auth/passkeys/'.Passkey::query()->sole()->getKey(), [], bearer($pair))->assertForbidden();

    $options = $this->postJson('/users/auth/reauthenticate/passkey/options', [], bearer($pair))->assertOk()->json();
    $this->postJson('/users/auth/reauthenticate', ['method' => 'passkey', 'credential' => assertionPayload($authenticator->assert(requestOptionsFrom($options)))], bearer($pair))->assertOk();

    $this->postJson('/users/auth/passkeys/options', [], bearer($pair))->assertOk();
});

it('refuses an email-code re-authentication made before a second factor was added', function (): void {
    $user = User::factory()->passwordless()->create();
    $pair = issuePair($user, amr: [AuthMethodReference::Email]);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    $this->postJson('/users/auth/reauthenticate/otp', [], bearer($pair))->assertStatus(202);
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;
    $this->postJson('/users/auth/reauthenticate', ['method' => 'email_otp', 'code' => $code], bearer($pair))->assertOk();

    enableTotp($user);

    $this->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('methods', ['totp', 'recovery_code']);
});

it('keeps password and email-code proofs for accounts without a second factor', function (): void {
    $this->configureGuard('users', ['login.email_otp' => true]);
    $user = User::factory()->create();

    $this->postJson('/users/auth/two-factor', [], bearer(emailCodeLogin($user)))->assertOk();
    $this->postJson('/users/auth/two-factor', [], bearer(passwordReauthenticatedSession($user)))->assertOk();

    $passwordless = User::factory()->passwordless()->create();
    $pair = issuePair($passwordless, amr: [AuthMethodReference::Email]);
    CarbonImmutable::setTestNow('2026-09-26 11:00:00');
    $this->postJson('/users/auth/reauthenticate/otp', [], bearer($pair))->assertStatus(202);
    $code = (string) sentNotification($passwordless, EmailOtpNotification::class)->data->code;
    $this->postJson('/users/auth/reauthenticate', ['method' => 'email_otp', 'code' => $code], bearer($pair))->assertOk();

    $this->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], bearer($pair))->assertOk();
});

it('accepts the password for second-factor accounts only when the guard allows it', function (): void {
    $this->configureGuard('users', ['reauthentication.require_second_factor_when_enrolled' => false]);
    $user = User::factory()->create();
    enableTotp($user);

    $this->deleteJson('/users/auth/two-factor', [], bearer(issuePair($user)))->assertOk();

    $other = User::factory()->create();
    enableTotp($other);
    $this->postJson('/users/auth/two-factor/recovery-codes', [], bearer(passwordReauthenticatedSession($other)))->assertOk();
});
