<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LogoutScope;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Events\TokensRefreshed;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Exceptions\SessionNotFound;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

it('mints access tokens with the session claims', function (): void {
    Event::fake([TokensIssued::class]);
    $user = User::factory()->create();
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');

    $pair = issuePair($user, amr: [AuthMethodReference::Pwd, AuthMethodReference::Otp]);
    $claims = claimsOf($pair);

    expect($claims->get('aud'))->toBe('app-users')
        ->and($claims->get('sub'))->toBe((string) $user->getKey())
        ->and($claims->get('tv'))->toBe(0)
        ->and($claims->sessionId())->toBe($pair->sessionId)
        ->and($claims->authMethods())->toBe(['pwd', 'otp'])
        ->and($claims->authTime())->toBe(CarbonImmutable::now()->getTimestamp())
        ->and($claims->get('grd'))->toBe('users')
        ->and($claims->get('email'))->toBe($user->email)
        ->and($claims->get('email_verified'))->toBeTrue()
        ->and($pair->accessTokenId)->toBe($claims->string('jti'));

    Event::assertDispatched(TokensIssued::class, fn (TokensIssued $event): bool => $event->sessionId === $pair->sessionId);
    CarbonImmutable::setTestNow();
});

it('honours the per-guard access ttl and email claim switch', function (): void {
    $this->configureGuard('users', ['tokens.access_ttl' => 120, 'tokens.include_email' => false]);
    $user = User::factory()->create();

    $claims = claimsOf(issuePair($user, amr: []));

    expect($claims->int('exp') - $claims->int('iat'))->toBe(120)
        ->and($claims->get('email'))->toBeNull()
        ->and($claims->has('amr'))->toBeFalse();
});

it('rotates a refresh token within the session, keeping amr, auth_time and device data', function (): void {
    Event::fake([TokensRefreshed::class]);
    $user = User::factory()->create();
    $pair = issuePair($user, amr: [AuthMethodReference::Pwd], context: new SessionContext('10.0.0.1', 'UA/1', deviceName: 'Laptop'));

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addMinutes(5));
    $refreshed = Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext('10.0.0.2', 'UA/2'));
    $claims = claimsOf($refreshed);

    expect($refreshed->sessionId)->toBe($pair->sessionId)
        ->and($refreshed->refreshToken)->not->toBe($pair->refreshToken)
        ->and($claims->authMethods())->toBe(['pwd'])
        ->and($claims->authTime())->toBe(claimsOf($pair)->authTime())
        ->and($claims->sessionId())->toBe($pair->sessionId);

    $row = RefreshToken::query()->whereNull('revoked_at')->sole();
    expect($row->meta['device_name'] ?? null)->toBe('Laptop')
        ->and($row->ip_address)->toBe('10.0.0.2');

    Event::assertDispatched(TokensRefreshed::class);
    CarbonImmutable::setTestNow();
});

it('refuses a used, unknown or foreign-guard refresh token and records the failure', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext);

    expect(fn () => Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext))->toThrow(InvalidRefreshToken::class)
        ->and(fn () => Authentication::guard('users')->refresh('nope', new SessionContext))->toThrow(InvalidRefreshToken::class)
        ->and(LoginActivity::query()->where('type', 'refresh')->where('outcome', 'failed_token')->count())->toBe(2);
});

it('revokes the family and refuses a refresh once the owner is disabled', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);
    $user->forceFill(['disabled_at' => now()])->save();

    expect(fn () => Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext))->toThrow(InvalidRefreshToken::class)
        ->and(RefreshToken::query()->whereNull('revoked_at')->count())->toBe(0);
});

it('revokes the family and refuses a refresh once the account moved past the version it was minted under', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);
    $user->forceFill(['token_version' => 1])->save();

    expect(RefreshToken::query()->sole()->meta['tv'] ?? null)->toBe(0)
        ->and(fn () => Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext))->toThrow(InvalidRefreshToken::class)
        ->and(RefreshToken::query()->whereNull('revoked_at')->count())->toBe(0)
        ->and(LoginActivity::query()->where('type', 'refresh')->where('reason', 'revoked')->count())->toBe(1);
});

it('keeps refreshing a session issued before its token version was recorded', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);
    $row = RefreshToken::query()->sole();
    $row->forceFill(['meta' => Arr::except($row->meta ?? [], 'tv')])->save();
    $user->forceFill(['token_version' => 1])->save();

    $refreshed = Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext);

    expect($refreshed->sessionId)->toBe($pair->sessionId)
        ->and(claimsOf($refreshed)->get('tv'))->toBe(1);
});

it('lists sessions with the current flag over http', function (): void {
    $user = User::factory()->create();
    $first = issuePair($user, context: new SessionContext('10.0.0.1', 'UA', deviceName: 'Phone'));
    $second = issuePair($user);

    $this->getJson('/users/auth/sessions', bearer($second))
        ->assertOk()
        ->assertJsonCount(2, 'data')
        ->assertJsonPath('data.0.id', $second->sessionId)
        ->assertJsonPath('data.0.current', true)
        ->assertJsonPath('data.1.current', false)
        ->assertJsonPath('data.1.device_name', 'Phone')
        ->assertJsonPath('data.1.auth_methods', ['pwd']);

    expect($first->sessionId)->not->toBe($second->sessionId);
});

it('logs out the current session', function (): void {
    Event::fake([LoggedOut::class]);
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->postJson('/users/auth/logout', [], bearer($pair))->assertNoContent();

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    expect(fn () => Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext))->toThrow(InvalidRefreshToken::class);
    Event::assertDispatched(LoggedOut::class, fn (LoggedOut $event): bool => $event->scope === LogoutScope::Current && $event->revoked === 1);
});

it('logs out one specific session and 404s foreign, unknown or malformed ids', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $mine = issuePair($user);
    $second = issuePair($user);
    $foreign = issuePair($other);

    $this->deleteJson('/users/auth/sessions/'.$second->sessionId, [], bearer($mine))->assertNoContent();
    $this->getJson('/users/auth/me', bearer($second))->assertUnauthorized();

    $this->deleteJson('/users/auth/sessions/'.$foreign->sessionId, [], bearer($mine))->assertNotFound()->assertJsonPath('code', 'not_found');
    $this->deleteJson('/users/auth/sessions/not-a-uuid', [], bearer($mine))->assertNotFound();
    $this->deleteJson('/users/auth/sessions/'.$second->sessionId, [], bearer($mine))->assertNotFound();
    $this->getJson('/users/auth/me', bearer($foreign))->assertOk();
});

it('logs out every other session but keeps the caller', function (): void {
    $user = User::factory()->create();
    $mine = issuePair($user);
    $a = issuePair($user);
    $b = issuePair($user);

    $this->postJson('/users/auth/logout/others', [], bearer($mine))->assertOk()->assertJsonPath('revoked', 2);

    $this->getJson('/users/auth/me', bearer($mine))->assertOk();
    $this->getJson('/users/auth/me', bearer($a))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($b))->assertUnauthorized();
});

it('retires the previous access token on refresh, so revoking a session kills every token it minted', function (): void {
    $user = User::factory()->create();
    $mine = issuePair($user);
    $stolen = issuePair($user);

    // A thief refreshes the stolen session, keeping the access token it already had.
    $refreshed = Authentication::guard('users')->refresh($stolen->refreshToken, new SessionContext('10.0.0.9', 'PestBrowser/1.0'));

    $this->getJson('/users/auth/me', bearer($stolen))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($refreshed))->assertOk();

    $this->postJson('/users/auth/logout/others', [], bearer($mine))->assertOk()->assertJsonPath('revoked', 1);

    $this->getJson('/users/auth/me', bearer($stolen))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($refreshed))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($mine))->assertOk();
});

it('logs out everywhere, killing every access token through the token version', function (): void {
    $user = User::factory()->create();
    $mine = issuePair($user);
    $other = issuePair($user);

    $this->postJson('/users/auth/logout/everywhere', [], bearer($mine))->assertOk()->assertJsonPath('revoked', 2);

    $this->getJson('/users/auth/me', bearer($mine))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($other))->assertUnauthorized();
    expect($user->fresh()?->tokenVersion())->toBe(1);
});

it('requires a recent authentication for logout everywhere when the login is stale', function (): void {
    $this->configureGuard('users', ['tokens.access_ttl' => 3600]);
    $user = User::factory()->create();
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
    $pair = issuePair($user);

    CarbonImmutable::setTestNow('2026-09-26 10:20:00');
    $this->postJson('/users/auth/logout/everywhere', [], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('code', 'reauthentication_required')
        ->assertJsonPath('methods', ['password']);
    CarbonImmutable::setTestNow();
});

it('caps active sessions, revoking the oldest', function (): void {
    $this->configureGuard('users', ['sessions.max_active' => 2]);
    $user = User::factory()->create();

    $first = issuePair($user);
    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());
    issuePair($user);
    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());
    issuePair($user);

    expect(Authentication::guard('users')->sessions($user))->toHaveCount(2)
        ->and(Authentication::guard('users')->sessions($user)->pluck('id'))->not->toContain($first->sessionId);
    CarbonImmutable::setTestNow();
});

it('logs out through the guard context', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);
    $current = CurrentToken::fromClaims(claimsOf($pair));
    $context = Authentication::guard('users');

    expect($context->logoutOthers($user, $current))->toBe(0);
    $context->logoutSession($user, $pair->sessionId);
    expect(fn () => $context->logoutSession($user, $pair->sessionId))->toThrow(SessionNotFound::class);

    $context->logout($user, $current);
    expect($context->logoutEverywhere($user))->toBe(0);
});

it('returns the account from me with the configured resource', function (): void {
    $user = User::factory()->create(['locale' => 'sk', 'timezone' => 'Europe/Bratislava']);

    $this->getJson('/users/auth/me', bearer(issuePair($user)))
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJsonPath('data.id', $user->getKey())
        ->assertJsonPath('data.locale', 'sk')
        ->assertJsonPath('data.timezone', 'Europe/Bratislava');
});
