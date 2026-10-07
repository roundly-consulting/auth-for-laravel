<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Events\Reauthenticated;
use RoundlyConsulting\Auth\Events\RecoveryCodeUsed;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Notifications\RecoveryCodeUsedNotification;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    $this->configureGuard('users', ['tokens.access_ttl' => 7200]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function staleSession(User $user): TokenPair
{
    $pair = issuePair($user);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    return $pair;
}

it('treats a fresh login as recent, and a stale one as not', function (): void {
    $user = User::factory()->create();
    $fresh = issuePair($user);

    $this->postJson('/users/auth/two-factor', [], bearer($fresh))->assertOk();

    $stale = staleSession(User::factory()->create());
    $this->postJson('/users/auth/two-factor', [], bearer($stale))->assertForbidden()->assertJsonPath('code', 'reauthentication_required');
});

it('reauthenticates with the password when the account has no second factor', function (): void {
    Event::fake([Reauthenticated::class]);
    $user = User::factory()->create();
    $pair = staleSession($user);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($pair))
        ->assertOk()
        ->assertJsonPath('status', 'confirmed')
        ->assertJsonPath('confirmed_until', '2026-09-26T10:45:00Z');

    $this->postJson('/users/auth/two-factor', [], bearer($pair))->assertOk();
    Event::assertDispatched(Reauthenticated::class);
});

it('keeps the marker per session', function (): void {
    $user = User::factory()->create();
    $first = issuePair($user);
    $second = issuePair($user);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($first))->assertOk();

    $this->postJson('/users/auth/two-factor', [], bearer($first))->assertOk();
    $this->postJson('/users/auth/two-factor', [], bearer($second))->assertForbidden();
});

it('refuses the password for an account with a second factor', function (): void {
    $user = User::factory()->create();
    $secret = enableTotp($user);
    $pair = staleSession($user);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($pair))
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_not_allowed');

    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('methods', ['totp', 'recovery_code']);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => totpCode($secret)], bearer($pair))->assertOk();
    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))->assertOk();
});

it('rejects a wrong password or code and throttles per session', function (): void {
    $this->configureGuard('users', ['throttle.reauthentication.max' => 2]);
    $user = User::factory()->create();
    $pair = staleSession($user);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'nope'], bearer($pair))->assertStatus(422)->assertJsonPath('code', 'invalid_credentials');
    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'nope'], bearer($pair))->assertStatus(422);
    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($pair))->assertStatus(429);
});

it('rejects a wrong totp code', function (): void {
    $user = User::factory()->create();
    enableTotp($user);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => '000000'], bearer(staleSession($user)))
        ->assertStatus(422)
        ->assertJsonPath('code', 'invalid_code');
});

it('lets a passwordless account reauthenticate with an email code', function (): void {
    Notification::fake();
    $user = User::factory()->passwordless()->create();
    $pair = staleSession($user);

    $this->postJson('/users/auth/reauthenticate/otp', [], bearer($pair))->assertStatus(202);
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;

    $this->postJson('/users/auth/reauthenticate', ['method' => 'email_otp', 'code' => '000000'], bearer($pair))
        ->assertStatus(422)
        ->assertJsonPath('attempts_left', 4);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'email_otp', 'code' => $code], bearer($pair))->assertOk();
});

it('refuses an email code for accounts with a password', function (): void {
    $this->postJson('/users/auth/reauthenticate/otp', [], bearer(staleSession(User::factory()->create())))
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_not_allowed');
});

it('refuses a locked account', function (): void {
    $user = User::factory()->create();
    $pair = staleSession($user);
    $user->forceFill(['locked_until' => CarbonImmutable::now()->addHour()])->save();

    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($pair))
        ->assertStatus(423)
        ->assertJsonPath('code', 'account_locked');
});

it('ignores a fresh login when fresh_login_counts is off', function (): void {
    $this->configureGuard('users', ['reauthentication.fresh_login_counts' => false]);

    $this->postJson('/users/auth/two-factor', [], bearer(issuePair(User::factory()->create())))->assertForbidden();
});

it('protects host routes with the middleware', function (): void {
    Route::middleware(['auth:users', 'authentication.reauthenticated:60,users'])->get('/_sudo', fn () => 'ok');
    $user = User::factory()->create();

    $this->get('/_sudo', bearer(issuePair($user)))->assertOk();
    CarbonImmutable::setTestNow('2026-09-26 10:02:00');
    $this->get('/_sudo', bearer(issuePair($user, context: null)))->assertOk();
});

it('lets a route with a longer window accept an explicit re-authentication older than the timeout', function (): void {
    Route::middleware(['auth:users', 'authentication.reauthenticated:3600,users'])->get('/_sudo', fn () => 'ok');
    $user = User::factory()->create();
    $pair = issuePair($user); // 10:00 — outside every window below, so only the marker can pass

    CarbonImmutable::setTestNow('2026-09-26 11:30:00');
    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], bearer($pair))
        ->assertOk()
        ->assertJsonPath('confirmed_until', '2026-09-26T11:45:00Z');

    // 20 minutes later: past the 900 s timeout, inside the route's 3600 s window.
    CarbonImmutable::setTestNow('2026-09-26 11:50:00');

    $this->get('/_sudo', bearer($pair))->assertOk();
    $this->postJson('/users/auth/two-factor', [], bearer($pair))->assertForbidden()->assertJsonPath('code', 'reauthentication_required');
});

it('announces a recovery code spent on a re-authentication and records it as such', function (string $claimed): void {
    Notification::fake();
    Event::fake([RecoveryCodeUsed::class, Reauthenticated::class]);
    $user = User::factory()->create();
    enableTotp($user);
    $pair = staleSession($user);

    $this->postJson('/users/auth/reauthenticate', ['method' => $claimed, 'code' => recoveryCodes()[0]], bearer($pair))->assertOk();

    Event::assertDispatched(RecoveryCodeUsed::class, fn (RecoveryCodeUsed $event): bool => $event->remaining === 2);
    Event::assertDispatched(Reauthenticated::class, fn (Reauthenticated $event): bool => $event->method === ReauthenticationMethod::RecoveryCode);
    Notification::assertSentTo($user, RecoveryCodeUsedNotification::class);
    expect(app(ReauthenticationMarker::class)->proof('users', $pair->sessionId)?->method)->toBe(ReauthenticationMethod::RecoveryCode);
})->with(['recovery_code', 'totp']);

it('checks the allow-list against the factor that actually matched', function (): void {
    Notification::fake();
    Event::fake([RecoveryCodeUsed::class, Reauthenticated::class]);
    $this->configureGuard('users', ['reauthentication.methods' => ['password', 'totp', 'passkey']]);
    $user = User::factory()->create();
    $secret = enableTotp($user);
    $pair = staleSession($user);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'recovery_code', 'code' => recoveryCodes()[0]], bearer($pair))
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_not_allowed');

    // Claimed as totp, but a recovery code matched: refused all the same.
    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => recoveryCodes()[0]], bearer($pair))
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_not_allowed');

    expect(app(ReauthenticationMarker::class)->proof('users', $pair->sessionId))->toBeNull();
    Event::assertNotDispatched(Reauthenticated::class);
    // The code is spent all the same, so the owner hears about it.
    Event::assertDispatched(RecoveryCodeUsed::class, fn (RecoveryCodeUsed $event): bool => $event->remaining === 2);
    Notification::assertSentTo($user, RecoveryCodeUsedNotification::class);

    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => totpCode($secret)], bearer($pair))->assertOk();
    expect(app(ReauthenticationMarker::class)->proof('users', $pair->sessionId)?->method)->toBe(ReauthenticationMethod::Totp);
});
