<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Account\LockAccount;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\AccountLockedNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    $this->configureGuard('users', ['lockout.enabled' => true, 'lockout.threshold' => 3, 'lockout.duration' => 600, 'throttle.login.max' => 100, 'throttle.login_account.max' => 100]);
});

it('never touches the counter while lockout is off', function (): void {
    $this->configureGuard('users', ['lockout.enabled' => false]);
    $user = User::factory()->create();

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'bad'), sessionContext()))->toThrow(InvalidCredentials::class)
        ->and($user->fresh()?->getAttribute('failed_login_count'))->toBe(0);
});

it('locks after the threshold and answers too_many_attempts even for the right password', function (): void {
    Event::fake([AccountLocked::class]);
    Notification::fake();
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
    $user = User::factory()->create();

    foreach (range(1, 3) as $attempt) {
        expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'bad'), sessionContext()))->toThrow(InvalidCredentials::class);
    }

    expect($user->fresh()?->isLocked())->toBeTrue()
        ->and($user->fresh()?->getAttribute('failed_login_count'))->toBe(0);

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'])
        ->assertStatus(429)
        ->assertJsonPath('code', 'too_many_attempts')
        ->assertJsonPath('retry_after', 600);

    Event::assertDispatched(AccountLocked::class);
    Notification::assertSentTo($user, AccountLockedNotification::class);
    CarbonImmutable::setTestNow();
});

it('does not count failures while locked, and unlocks lazily', function (): void {
    $user = User::factory()->create(['locked_until' => CarbonImmutable::now()->addMinute()]);

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'bad'), sessionContext()))->toThrow(TooManyAttempts::class)
        ->and($user->fresh()?->getAttribute('failed_login_count'))->toBe(0);

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addMinutes(2));
    expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->isAuthenticated())->toBeTrue();
    CarbonImmutable::setTestNow();
});

it('resets the counter on success', function (): void {
    $user = User::factory()->create();

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'bad'), sessionContext()))->toThrow(InvalidCredentials::class)
        ->and($user->fresh()?->getAttribute('failed_login_count'))->toBe(1);

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect($user->fresh()?->getAttribute('failed_login_count'))->toBe(0);
});

it('never revokes existing sessions when locking', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    foreach (range(1, 3) as $attempt) {
        expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'bad'), sessionContext()))->toThrow(InvalidCredentials::class);
    }

    $this->getJson('/users/auth/me', bearer($pair))->assertOk();
});

it('notifies the owner of a manual lock exactly like an automatic one', function (): void {
    Notification::fake();
    $user = User::factory()->create();

    app(LockAccount::class)->execute('users', $user, 120);

    Notification::assertSentTo($user, AccountLockedNotification::class);
});
