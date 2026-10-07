<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use PHPUnit\Framework\AssertionFailedError;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\ResetPasswordNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

it('does not pass for an account whose version only moved before the test acted', function (): void {
    // An account whose version moved earlier (an older logout everywhere, say).
    $user = User::factory()->create(['token_version' => 3]);
    $this->actingAsAccount($user);

    expect(fn () => $this->assertTokensInvalidated($user, InvalidationReason::PasswordChanged))->toThrow(AssertionFailedError::class)
        ->and(fn () => $this->assertTokensInvalidated($user, InvalidationReason::PasswordChanged, since: 3))->toThrow(AssertionFailedError::class);
});

it('passes once the version moved since the baseline, and demands one', function (): void {
    $user = User::factory()->create(['token_version' => 3]);

    expect(fn () => $this->assertTokensInvalidated($user, InvalidationReason::Security))->toThrow(AssertionFailedError::class, 'baseline');

    $this->actingAsAccount($user);
    Authentication::guard('users')->invalidate($user, InvalidationReason::Security);

    $this->assertTokensInvalidated($user, InvalidationReason::Security)
        ->assertTokensInvalidated($user, InvalidationReason::Security, since: 3);
});

it('accepts a correctly applied none scope, and fails when it moved anyway', function (): void {
    $user = User::factory()->create();
    $this->actingAsAccount($user);

    // passkey_changed defaults to `none`: nothing to invalidate, and nothing was.
    Authentication::guard('users')->invalidate($user, InvalidationReason::PasskeyChanged);
    $this->assertTokensInvalidated($user, InvalidationReason::PasskeyChanged);

    Authentication::guard('users')->invalidate($user, InvalidationReason::Security);
    expect(fn () => $this->assertTokensInvalidated($user, InvalidationReason::PasskeyChanged))->toThrow(AssertionFailedError::class);
});

it('announces the pair actingAsAccount issues, like any host-issued login', function (): void {
    Event::fake([TokensIssued::class]);
    $user = User::factory()->create();

    $this->actingAsAccount($user);

    Event::assertDispatched(TokensIssued::class, fn (TokensIssued $event): bool => $event->guard === 'users'
        && $event->sessionId === $this->authenticationTokens?->sessionId);
});

/**
 * Regression (chat review C-15): under scope `all` the helper demanded zero sessions, so it
 * failed on correct code whenever a login followed the invalidation (a reset with
 * `passwords.reset.login_after`). It now checks the sessions actingAsAccount saw.
 */
it('passes for an all-scope invalidation followed by a fresh login', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['passwords.reset.login_after' => true, 'two_factor.after_email_login' => false]);
    $user = User::factory()->create();
    issuePair($user);
    $this->actingAsAccount($user);

    $this->postJson('/users/auth/password/forgot', ['email' => $user->email])->assertStatus(202);
    $token = tokenFromUrl(sentNotification($user, ResetPasswordNotification::class)->data->url);

    $this->postJson('/users/auth/password/reset', ['token' => $token, 'password' => 'a-brand-new-passphrase'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect(RefreshTokens::sessions($user)->all())->toHaveCount(1);

    $this->assertTokensInvalidated($user, InvalidationReason::PasswordReset);
});

it('fails an all-scope invalidation that left a session it saw alive', function (): void {
    $user = User::factory()->create();
    $kept = issuePair($user);
    $this->actingAsAccount($user);

    // The version moves, but the earlier session is never revoked.
    $user->forceFill(['token_version' => $user->tokenVersion() + 1])->save();
    RefreshTokens::sessions($user)->revoke((string) $this->authenticationTokens?->sessionId);

    expect(RefreshTokens::sessions($user)->find($kept->sessionId))->not->toBeNull()
        ->and(fn () => $this->assertTokensInvalidated($user, InvalidationReason::PasswordReset))
        ->toThrow(AssertionFailedError::class, 'survived');
});

it('demands zero sessions under all when only since: is given', function (): void {
    $user = User::factory()->create(['token_version' => 3]);
    issuePair($user);

    Authentication::guard('users')->invalidate($user, InvalidationReason::PasswordReset);
    $this->assertTokensInvalidated($user, InvalidationReason::PasswordReset, since: 3);

    issuePair($user);

    expect(fn () => $this->assertTokensInvalidated($user, InvalidationReason::PasswordReset, since: 3))
        ->toThrow(AssertionFailedError::class, 'survived');
});

/**
 * Regression (chat review C-16): without a guard the helper read the DEFAULT guard's scope, not
 * the account's — a `clients` account with clients `others` and users `none` passed although
 * nothing was invalidated. It now resolves the guard like actingAsAccount (owning).
 */
it('judges an account by its own guard, refusing a foreign one', function (): void {
    $this->configureGuard('clients', ['invalidation.password_changed' => 'others']);
    $this->configureGuard('users', ['invalidation.password_changed' => 'none']);
    $client = Client::factory()->create();
    $this->actingAsAccount($client, 'clients');

    expect(fn () => $this->assertTokensInvalidated($client, InvalidationReason::PasswordChanged))
        ->toThrow(AuthenticationMisconfigured::class, 'belongs to another guard than [users]')
        ->and(fn () => $this->assertTokensInvalidated($client, InvalidationReason::PasswordChanged, 'clients'))
        ->toThrow(AssertionFailedError::class, 'did not move');

    Authentication::guard('clients')->invalidate($client, InvalidationReason::PasswordChanged);

    $this->assertTokensInvalidated($client, InvalidationReason::PasswordChanged, 'clients');
});
