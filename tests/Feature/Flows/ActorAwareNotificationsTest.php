<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\DataTransferObjects\ActorData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Events\AccountTokensInvalidated;
use RoundlyConsulting\Auth\Events\PasskeyRemoved;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Events\TwoFactorDisabled;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\AccountLockedNotification;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;
use RoundlyConsulting\Auth\Notifications\PasskeyRemovedNotification;
use RoundlyConsulting\Auth\Notifications\PasswordChangedNotification;
use RoundlyConsulting\Auth\Notifications\TwoFactorDisabledNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Operator;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/*
 * The four host-callable writes another person can make for an account. With another
 * actor the owner is told an administrator acted (the `by_actor` copy) and the event
 * carries the actor; without one — or with the account itself — nothing changes.
 */

/**
 * @return array{event: class-string, notification: class-string<AuthenticationNotification>, base: list<string>, by_actor: list<string>, by_actor_sk: list<string>}
 */
function actorWrite(string $write): array
{
    return match ($write) {
        'set' => [
            'event' => PasswordChanged::class,
            'notification' => PasswordChangedNotification::class,
            'base' => ['Your Roundly password was changed', 'The password of your account was just changed.', 'If this was not you, reset your password immediately.'],
            'by_actor' => ['Your Roundly password was changed by an administrator', 'An administrator changed the password of your account.', 'If you did not expect this, contact support immediately.'],
            'by_actor_sk' => ['Vaše heslo do aplikácie Roundly zmenil administrátor', 'Administrátor zmenil heslo k vášmu účtu.', 'Ak ste to nečakali, okamžite kontaktujte podporu.'],
        ],
        'two_factor' => [
            'event' => TwoFactorDisabled::class,
            'notification' => TwoFactorDisabledNotification::class,
            'base' => ['Two-factor authentication disabled', 'Two-factor authentication was disabled on your account.', 'If this was not you, contact support immediately.'],
            'by_actor' => ['Two-factor authentication disabled by an administrator', 'An administrator disabled two-factor authentication on your account.', 'If you did not expect this, contact support immediately and turn two-factor authentication back on.'],
            'by_actor_sk' => ['Dvojfaktorové overenie vypol administrátor', 'Administrátor vypol vo vašom účte dvojfaktorové overenie.', 'Ak ste to nečakali, okamžite kontaktujte podporu a dvojfaktorové overenie znova zapnite.'],
        ],
        'passkey' => [
            'event' => PasskeyRemoved::class,
            'notification' => PasskeyRemovedNotification::class,
            'base' => ['A passkey was removed from your account', 'A passkey was removed from your account.', 'If this was not you, contact support immediately.'],
            'by_actor' => ['An administrator removed a passkey from your account', 'An administrator removed a passkey from your account. It can no longer be used to sign in.', 'If you did not expect this, contact support immediately.'],
            'by_actor_sk' => ['Administrátor odstránil z vášho účtu prístupový kľúč', 'Administrátor odstránil z vášho účtu prístupový kľúč. Na prihlásenie ho už nemožno použiť.', 'Ak ste to nečakali, okamžite kontaktujte podporu.'],
        ],
        'lock' => [
            'event' => AccountLocked::class,
            'notification' => AccountLockedNotification::class,
            'base' => ['Your Roundly account was locked', 'Your account was temporarily locked after too many failed sign-in attempts.', 'If these attempts were not yours, consider changing your password.'],
            'by_actor' => ['Your Roundly account was locked by an administrator', 'An administrator temporarily locked your account. You cannot sign in until the lock ends.', 'If you did not expect this, contact support.'],
            'by_actor_sk' => ['Váš účet v aplikácii Roundly zablokoval administrátor', 'Administrátor dočasne zablokoval váš účet. Kým blokovanie neskončí, nemôžete sa prihlásiť.', 'Ak ste to nečakali, kontaktujte podporu.'],
        ],
    };
}

/**
 * Give the account what the write takes away (a TOTP enrolment, a passkey).
 */
function prepareActorWrite(string $write, User $user): void
{
    match ($write) {
        'two_factor' => enableTotp($user),
        'passkey' => addPasskey($user),
        default => null,
    };
}

/**
 * Run the write through the facade, passing the actor by name.
 */
function runActorWrite(string $write, User $user, ?Model $actor, ?CurrentToken $current = null): void
{
    match ($write) {
        'set' => Authentication::passwords()->set($user, 'n3w-Passphrase!', InvalidationReason::Security, actor: $actor),
        'two_factor' => Authentication::twoFactor()->disable($user, $current, actor: $actor),
        'passkey' => Authentication::passkeys()->remove($user, (int) Authentication::passkeys()->all($user)->firstOrFail()->getKey(), $current, actor: $actor),
        'lock' => Authentication::lock($user, seconds: 3600, actor: $actor),
    };
}

/**
 * The write did not happen: the password, the TOTP enrolment, the passkey and the lock
 * state are what they were.
 */
function expectActorWriteUndone(string $write, User $user): void
{
    $fresh = $user->fresh();

    match ($write) {
        'set' => expect(Hash::check('correct-horse-battery', (string) $fresh?->password))->toBeTrue(),
        'two_factor' => expect($fresh?->hasTwoFactorEnabled())->toBeTrue(),
        'passkey' => expect(Authentication::passkeys()->all($user))->toHaveCount(1),
        'lock' => expect($fresh?->isLocked())->toBeFalse(),
    };
}

/**
 * @param  class-string<AuthenticationNotification>  $class
 * @return list<string> subject, intro, outro of the mail as the account would read it
 */
function actorMailLines(User $user, string $class): array
{
    $mail = sentNotification($user, $class)->toMail($user);
    // Without an action every line is an intro line: the outro is the last one.
    $lines = [...$mail->introLines, ...$mail->outroLines];

    return [(string) $mail->subject, (string) $lines[0], (string) end($lines)];
}

dataset('actor-aware writes', ['set', 'two_factor', 'passkey', 'lock']);

beforeEach(function (): void {
    config()->set('app.name', 'Roundly');
});

it('tells the owner an administrator acted and puts the actor on the event', function (string $write): void {
    Notification::fake();
    $spec = actorWrite($write);
    Event::fake([$spec['event']]);
    $user = User::factory()->create();
    $admin = User::factory()->create();
    prepareActorWrite($write, $user);

    runActorWrite($write, $user, $admin);

    Event::assertDispatched($spec['event'], fn (object $event): bool => $event->actor instanceof User && $event->actor->is($admin));
    $notification = sentNotification($user, $spec['notification']);

    expect($notification->data->actor)->toBeInstanceOf(ActorData::class)
        ->and($notification->data->actor?->is($admin))->toBeTrue()
        ->and($notification->data->actor?->is($user))->toBeFalse()
        ->and(actorMailLines($user, $spec['notification']))->toBe($spec['by_actor'])
        ->and($notification->toMail($user)->actionText)->toBeNull();
})->with('actor-aware writes');

it('mails the administrator copy in the account locale', function (string $write): void {
    $spec = actorWrite($write);
    $user = User::factory()->create(['locale' => 'sk']);
    $admin = User::factory()->create();
    prepareActorWrite($write, $user);

    runActorWrite($write, $user, $admin);

    $messages = app('mailer')->getSymfonyTransport()->messages();
    $message = $messages[count($messages) - 1]->getOriginalMessage();
    [$subject, $intro, $outro] = $spec['by_actor_sk'];

    expect($message->getSubject())->toBe($subject)
        ->and((string) $message->getTextBody())->toContain($intro)->toContain($outro);
})->with('actor-aware writes');

it('treats the account acting on itself as no actor', function (string $write): void {
    Notification::fake();
    $spec = actorWrite($write);
    Event::fake([$spec['event']]);
    $user = User::factory()->create();
    prepareActorWrite($write, $user);

    runActorWrite($write, $user, User::query()->findOrFail($user->getKey()));

    Event::assertDispatched($spec['event'], fn (object $event): bool => $event->actor === null);

    expect(sentNotification($user, $spec['notification'])->data->actor)->toBeNull()
        ->and(actorMailLines($user, $spec['notification']))->toBe($spec['base']);
})->with('actor-aware writes');

it('keeps today\'s copy and a null actor when none is given', function (string $write): void {
    Notification::fake();
    $spec = actorWrite($write);
    Event::fake([$spec['event']]);
    $user = User::factory()->create();
    prepareActorWrite($write, $user);

    runActorWrite($write, $user, null);

    Event::assertDispatched($spec['event'], fn (object $event): bool => $event->actor === null);

    expect(sentNotification($user, $spec['notification'])->data->actor)->toBeNull()
        ->and(actorMailLines($user, $spec['notification']))->toBe($spec['base']);
})->with('actor-aware writes');

it('accepts an actor of another guard and one that is no account', function (string $write, string $kind): void {
    Notification::fake();
    $spec = actorWrite($write);
    Event::fake([$spec['event']]);
    $user = User::factory()->create();
    // Same primary key as the account on another table: still someone else.
    $actor = $kind === 'client' ? Client::factory()->create(['id' => $user->getKey()]) : Operator::factory()->create();
    prepareActorWrite($write, $user);

    runActorWrite($write, $user, $actor);

    Event::assertDispatched($spec['event'], fn (object $event): bool => $event->actor instanceof Model && $event->actor->is($actor));

    expect(sentNotification($user, $spec['notification'])->data->actor?->is($actor))->toBeTrue()
        ->and(actorMailLines($user, $spec['notification']))->toBe($spec['by_actor']);
})->with('actor-aware writes')->with(['client', 'operator']);

it('refuses an unsaved actor before anything is written', function (string $write): void {
    Notification::fake();
    $spec = actorWrite($write);
    Event::fake([$spec['event'], AccountTokensInvalidated::class]);
    $user = User::factory()->create();
    prepareActorWrite($write, $user);

    expect(fn () => runActorWrite($write, $user, new Operator(['email' => 'nobody@example.com'])))
        ->toThrow(InvalidArgumentException::class, 'The actor must be a saved model.');

    expectActorWriteUndone($write, $user);
    Event::assertNotDispatched($spec['event']);
    Event::assertNotDispatched(AccountTokensInvalidated::class);
    Notification::assertNothingSent();
})->with('actor-aware writes');

it('refuses another actor together with a current token, changing nothing', function (string $write, string $token): void {
    Notification::fake();
    $spec = actorWrite($write);
    Event::fake([$spec['event'], AccountTokensInvalidated::class]);
    $this->configureGuard('users', ['invalidation.passkey_changed' => 'others']);
    $user = User::factory()->create();
    $admin = User::factory()->create();
    prepareActorWrite($write, $user);
    $userPair = issuePair($user);
    $adminPair = issuePair($admin);
    // The admin's own token, or the account's: with another actor neither is kept.
    $current = currentTokenOf($token === 'admin' ? $adminPair : $userPair);

    expect(fn () => runActorWrite($write, $user, $admin, $current))
        ->toThrow(InvalidArgumentException::class, 'Another actor cannot keep a current token: leave out $current when passing actor:.');

    expectActorWriteUndone($write, $user);
    Event::assertNotDispatched($spec['event']);
    Event::assertNotDispatched(AccountTokensInvalidated::class);
    Notification::assertNothingSent();
    $this->getJson('/users/auth/me', bearer($userPair))->assertOk();
    $this->getJson('/users/auth/me', bearer($adminPair))->assertOk();
})->with(['two_factor', 'passkey'])->with(['admin', 'own']);

it('keeps the current token when the account itself is the actor', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    enableTotp($user);
    $pair = issuePair($user);

    $tokens = Authentication::twoFactor()->disable($user, currentTokenOf($pair), sessionContext(), actor: $user);

    expect($tokens)->not->toBeNull()
        ->and(sentNotification($user, TwoFactorDisabledNotification::class)->data->actor)->toBeNull();
    $this->getJson('/users/auth/me', bearer($tokens))->assertOk();
});

it('keeps the automatic lockout copy', function (): void {
    Notification::fake();
    Event::fake([AccountLocked::class]);
    $this->configureGuard('users', ['lockout.enabled' => true, 'lockout.threshold' => 2, 'throttle.login.max' => 100, 'throttle.login_account.max' => 100]);
    $user = User::factory()->create();

    foreach (range(1, 2) as $attempt) {
        expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'bad'), sessionContext()))->toThrow(InvalidCredentials::class);
    }

    Event::assertDispatched(AccountLocked::class, fn (AccountLocked $event): bool => $event->actor === null);

    expect(sentNotification($user, AccountLockedNotification::class)->data->actor)->toBeNull()
        ->and(actorMailLines($user, AccountLockedNotification::class))->toBe(actorWrite('lock')['base']);
});

it('takes the actor through a named guard, the injected manager and the action', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $admin = User::factory()->create();

    Authentication::guard('users')->lock($user, actor: $admin);
    app(AuthenticationManager::class)->unlock($user);
    app(AuthenticationManager::class)->lock($user, 60, $admin);
    app(SetPassword::class)->execute('users', $user, 'n3w-Passphrase!', actor: $admin);

    $locks = Notification::sent($user, AccountLockedNotification::class);

    expect($locks)->toHaveCount(2)
        ->and($locks->every(fn (AccountLockedNotification $sent): bool => $sent->data->actor?->is($admin) === true))->toBeTrue()
        ->and(sentNotification($user, PasswordChangedNotification::class)->data->actor?->is($admin))->toBeTrue();
});
