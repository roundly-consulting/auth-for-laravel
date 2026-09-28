<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\AssertionFailedError;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

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
