<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\LoginThrottled;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

function failLogin(string $identifier, string $ip = '10.0.0.1'): void
{
    try {
        Authentication::guard('users')->attempt(new PasswordCredentials($identifier, 'wrong-password'), sessionContext(ip: $ip));
    } catch (InvalidCredentials) {
        // counted
    }
}

it('throttles identifier+ip after five failures, with Retry-After, before any hashing', function (): void {
    Event::fake([LoginThrottled::class]);
    $user = User::factory()->create();

    foreach (range(1, 5) as $attempt) {
        failLogin($user->email);
    }

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'], ['REMOTE_ADDR' => '10.0.0.1'])
        ->assertStatus(429)
        ->assertHeader('Retry-After')
        ->assertJsonPath('code', 'too_many_attempts');

    expect(LoginActivity::query()->where('outcome', 'throttled')->count())->toBe(1);
    Event::assertDispatched(LoginThrottled::class, fn (LoginThrottled $event): bool => $event->kind === ThrottleKind::Login && $event->retryAfter > 0);
});

it('does not throttle the same identifier from another ip', function (): void {
    $user = User::factory()->create();

    foreach (range(1, 5) as $attempt) {
        failLogin($user->email, '10.0.0.1');
    }

    expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext(ip: '10.0.0.2'))->isAuthenticated())->toBeTrue();
});

it('caps an identifier across ips and an ip across identifiers', function (): void {
    $this->configureGuard('users', ['throttle.login_account.max' => 3, 'throttle.login_ip.max' => 4]);
    $user = User::factory()->create();

    foreach (['1.1.1.1', '1.1.1.2', '1.1.1.3'] as $ip) {
        failLogin($user->email, $ip);
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext(ip: '1.1.1.9')))->toThrow(TooManyAttempts::class);

    foreach (['a@x.test', 'b@x.test', 'c@x.test', 'd@x.test'] as $identifier) {
        failLogin($identifier, '9.9.9.9');
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials('e@x.test', 'x'), sessionContext(ip: '9.9.9.9')))->toThrow(TooManyAttempts::class);
});

it('clears the identifier+ip bucket on success but not the volumetric ones', function (): void {
    $this->configureGuard('users', ['throttle.login_ip.max' => 6]);
    $user = User::factory()->create();

    foreach (range(1, 4) as $attempt) {
        failLogin($user->email);
    }

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    foreach (range(1, 2) as $attempt) {
        failLogin($user->email);
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))->toThrow(TooManyAttempts::class);
});

it('never counts a success toward the limit', function (): void {
    $user = User::factory()->create();

    foreach (range(1, 8) as $attempt) {
        expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->isAuthenticated())->toBeTrue();
    }
});
