<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Account\UnlockAccount;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\Events\AccountDisabled;
use RoundlyConsulting\Auth\Events\AccountEnabled;
use RoundlyConsulting\Auth\Events\AccountTokensInvalidated;
use RoundlyConsulting\Auth\Events\AccountUnlocked;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Operator;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/*
 * The account-state siblings of `lock()`: `disable()`, `enable()` and `unlock()` take the
 * same `actor:` and put it on their event. They send no notification, with or without one.
 */

/**
 * @return class-string
 */
function accountStateEvent(string $write): string
{
    return match ($write) {
        'disable' => AccountDisabled::class,
        'enable' => AccountEnabled::class,
        'unlock' => AccountUnlocked::class,
    };
}

/**
 * An account the write can act on: an active one to disable, a disabled one to enable, a
 * locked one to unlock.
 */
function accountForStateWrite(string $write): User
{
    return match ($write) {
        'disable' => User::factory()->create(),
        'enable' => User::factory()->disabled()->create(),
        'unlock' => User::factory()->create(['locked_until' => now()->addHour()]),
    };
}

function runAccountStateWrite(string $write, User $user, ?Model $actor): void
{
    match ($write) {
        'disable' => Authentication::disable($user, 'fraud review', actor: $actor),
        'enable' => Authentication::enable($user, actor: $actor),
        'unlock' => Authentication::unlock($user, actor: $actor),
    };
}

/**
 * Whether the write took effect on the account.
 */
function accountStateWritten(string $write, User $user): bool
{
    $fresh = $user->fresh();

    return match ($write) {
        'disable' => $fresh?->isDisabled() === true,
        'enable' => $fresh?->isDisabled() === false,
        'unlock' => $fresh?->isLocked() === false,
    };
}

dataset('account-state writes', ['disable', 'enable', 'unlock']);

beforeEach(function (): void {
    Notification::fake();
});

it('puts another actor on the event and sends no notification', function (string $write, string $kind): void {
    $event = accountStateEvent($write);
    Event::fake([$event]);
    $user = accountForStateWrite($write);
    $actor = $kind === 'admin' ? User::factory()->create() : Operator::factory()->create();

    runAccountStateWrite($write, $user, $actor);

    expect(accountStateWritten($write, $user))->toBeTrue();
    Event::assertDispatched($event, fn (object $dispatched): bool => $dispatched->actor instanceof Model && $dispatched->actor->is($actor));
    Notification::assertNothingSent();
})->with('account-state writes')->with(['admin', 'operator']);

it('dispatches a null actor for the account itself or none', function (string $write, bool $self): void {
    $event = accountStateEvent($write);
    Event::fake([$event]);
    $user = accountForStateWrite($write);

    runAccountStateWrite($write, $user, $self ? User::query()->findOrFail($user->getKey()) : null);

    expect(accountStateWritten($write, $user))->toBeTrue();
    Event::assertDispatched($event, fn (object $dispatched): bool => $dispatched->actor === null);
})->with('account-state writes')->with(['self' => true, 'none' => false]);

it('refuses an unsaved actor before anything is written', function (string $write): void {
    $event = accountStateEvent($write);
    Event::fake([$event, AccountTokensInvalidated::class]);
    $user = accountForStateWrite($write);

    expect(fn () => runAccountStateWrite($write, $user, new Operator(['email' => 'nobody@example.com'])))
        ->toThrow(InvalidArgumentException::class, 'The actor must be a saved model.');

    expect(accountStateWritten($write, $user))->toBeFalse();
    Event::assertNotDispatched($event);
    Event::assertNotDispatched(AccountTokensInvalidated::class);
})->with('account-state writes');

it('takes the actor through a named guard, the injected manager and the action', function (): void {
    Event::fake([AccountDisabled::class, AccountEnabled::class, AccountUnlocked::class]);
    $user = User::factory()->create(['locked_until' => now()->addHour()]);
    $admin = User::factory()->create();

    Authentication::guard('users')->disable($user, actor: $admin);
    app(AuthenticationManager::class)->enable($user, $admin);
    app(UnlockAccount::class)->execute('users', $user, $admin);

    expect($user->fresh()?->isDisabled())->toBeFalse()
        ->and($user->fresh()?->isLocked())->toBeFalse();

    foreach ([AccountDisabled::class, AccountEnabled::class, AccountUnlocked::class] as $event) {
        Event::assertDispatched($event, fn (object $dispatched): bool => $dispatched->actor?->is($admin) === true);
    }

    Event::assertDispatched(AccountDisabled::class, fn (AccountDisabled $dispatched): bool => $dispatched->reason === null);
});
