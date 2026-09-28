<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

/**
 * An account with a second factor re-proves itself WITH it: neither a password (or email
 * code) re-authentication nor a fresh login that skipped the factor satisfies a sensitive
 * action gate — including when the factor was enrolled after that proof.
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

it('does not let a fresh email-code login that skipped totp disable it', function (): void {
    $this->configureGuard('users', ['login.email_otp' => true, 'two_factor.after_email_login' => false]);
    $user = User::factory()->create();
    $secret = enableTotp($user);
    $pair = emailCodeLogin($user);

    expect(claimsOf($pair)->authMethods())->toBe(['otp']);

    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('code', 'reauthentication_required')
        ->assertJsonPath('methods', ['totp', 'recovery_code']);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => totpCode($secret)], bearer($pair))->assertOk();
    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))->assertOk();
});

it('does not count a fresh password login once a second factor is added after it', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);
    enableTotp($user);

    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))->assertForbidden();
    $this->postJson('/users/auth/two-factor/recovery-codes', [], bearer($pair))->assertForbidden();

    $passkeyUser = User::factory()->create();
    $passkeyPair = issuePair($passkeyUser);
    addPasskey($passkeyUser);

    $this->postJson('/users/auth/passkeys/options', [], bearer($passkeyPair))->assertForbidden()->assertJsonPath('methods', ['passkey']);
});

it('counts a fresh login that used totp', function (): void {
    $user = User::factory()->create();
    $secret = enableTotp($user);

    $token = $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertJsonPath('status', 'challenge')
        ->json('challenge_token');
    $access = $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => totpCode($secret)], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertJsonPath('status', 'authenticated')
        ->json('access_token');

    $this->deleteJson('/users/auth/two-factor', [], ['Authorization' => 'Bearer '.$access, 'User-Agent' => 'PestBrowser/1.0'])->assertOk();
});

it('counts a fresh email-code login that went through the second factor', function (): void {
    $this->configureGuard('users', ['login.email_otp' => true]);
    $user = User::factory()->create();
    $secret = enableTotp($user);

    $this->postJson('/users/auth/login/otp', ['email' => $user->email])->assertStatus(202);
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;
    $token = $this->postJson('/users/auth/login/otp/verify', ['email' => $user->email, 'code' => $code], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertJsonPath('status', 'challenge')
        ->json('challenge_token');
    $access = $this->postJson('/users/auth/challenge/two-factor', ['challenge_token' => $token, 'code' => totpCode($secret)], ['User-Agent' => 'PestBrowser/1.0'])
        ->json('access_token');

    $this->postJson('/users/auth/two-factor/recovery-codes', [], ['Authorization' => 'Bearer '.$access, 'User-Agent' => 'PestBrowser/1.0'])->assertOk();
});

it('counts a fresh passkey login for an account with a passkey', function (): void {
    $user = User::factory()->create();
    $passkey = addPasskey($user);
    addPasskey($user);

    $this->deleteJson('/users/auth/passkeys/'.$passkey->getKey(), [], bearer(issuePair($user, amr: [AuthMethodReference::Hwk, AuthMethodReference::User, AuthMethodReference::Mfa])))
        ->assertOk();
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

it('applies the same rule on host routes behind the middleware', function (): void {
    Route::middleware(['auth:users', 'authentication.reauthenticated:300,users'])->get('/_sudo', fn () => 'ok');
    $user = User::factory()->create();
    enableTotp($user);

    $this->get('/_sudo', bearer(issuePair($user)))->assertForbidden();
    $this->get('/_sudo', bearer(issuePair($user, amr: [AuthMethodReference::Pwd, AuthMethodReference::Otp, AuthMethodReference::Mfa])))->assertOk();
});

it('never treats a session without a recorded auth_time as a fresh login', function (): void {
    $user = User::factory()->create();

    // A session the host issued without the package's metadata (a pre-adoption family).
    $issued = RefreshTokens::issue($user, new IssueContext(ipAddress: '10.0.0.1', userAgent: 'PestBrowser/1.0'));

    CarbonImmutable::setTestNow('2026-09-26 18:00:00');

    $access = $this->postJson('/users/auth/refresh', ['refresh_token' => $issued->plainText], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->json('access_token');

    expect(Jwt::verify($access, 'app-users')->authTime())->toBe(CarbonImmutable::parse('2026-09-26 10:00:00')->getTimestamp());

    $this->postJson('/users/auth/logout/everywhere', [], ['Authorization' => 'Bearer '.$access, 'User-Agent' => 'PestBrowser/1.0'])
        ->assertForbidden()
        ->assertJsonPath('code', 'reauthentication_required');
});

it('keeps the session start as auth_time when re-issuing a session without one', function (): void {
    $user = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext(ipAddress: '10.0.0.1', userAgent: 'PestBrowser/1.0'));

    CarbonImmutable::setTestNow('2026-09-26 18:00:00');

    $keep = new CurrentToken('kept-jti', CarbonImmutable::now()->addMinutes(5), $issued->token->family_id);
    $pair = Authentication::guard('users')->invalidate($user, InvalidationReason::PasswordChanged, $keep, sessionContext());

    expect($pair)->not->toBeNull()
        ->and(claimsOf($pair)->authTime())->toBe(CarbonImmutable::parse('2026-09-26 10:00:00')->getTimestamp());
});
