<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Auth\Actions\Account\DisableAccount;
use RoundlyConsulting\Auth\Actions\Account\LockAccount;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\AccountDisabled;
use RoundlyConsulting\Auth\Events\AccountEnabled;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Events\AccountUnlocked;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('disables an account, ending every session, and enables it again', function (): void {
    Event::fake([AccountDisabled::class, AccountEnabled::class]);
    $user = User::factory()->create();
    $pair = issuePair($user);

    app(DisableAccount::class)->execute('users', $user, 'fraud review');

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    expect($user->fresh()?->isDisabled())->toBeTrue()
        ->and($user->fresh()?->getAttribute('disabled_reason'))->toBe('fraud review');
    $this->assertTokensInvalidated($user, InvalidationReason::AccountDisabled, since: 0);

    Authentication::guard('users')->enable($user);
    expect($user->fresh()?->isDisabled())->toBeFalse();

    Authentication::guard('users')->disable($user);
    expect($user->fresh()?->isDisabled())->toBeTrue();

    Event::assertDispatched(AccountDisabled::class);
    Event::assertDispatched(AccountEnabled::class);
});

it('locks and unlocks an account', function (): void {
    Event::fake([AccountLocked::class, AccountUnlocked::class]);
    $user = User::factory()->create();

    app(LockAccount::class)->execute('users', $user, 60);
    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))->toThrow(InvalidCredentials::class);
    $this->assertLoginActivity('users', ActivityType::PasswordLogin, ActivityOutcome::Locked);

    Authentication::guard('users')->unlock($user);
    expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->isAuthenticated())->toBeTrue();

    Event::assertDispatched(AccountLocked::class);
    Event::assertDispatched(AccountUnlocked::class);
});

it('acts as an account through the testing helper', function (): void {
    $user = User::factory()->create();

    $this->actingAsAccount($user)->getJson('/users/auth/me')->assertOk()->assertJsonPath('data.id', $user->getKey());
});
