<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\Events\AccountDisabled;
use RoundlyConsulting\Auth\Events\AccountEnabled;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Events\AccountUnlocked;
use RoundlyConsulting\Auth\Events\InvitationCreated;
use RoundlyConsulting\Auth\Events\PasskeyRemoved;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Events\TwoFactorDisabled;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Operator;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * A host's queued listener serializes the event: a model must travel as its identifier
 * (as Laravel's own auth events do), never with its attributes — the password hash, stale
 * state — in the queue store or `failed_jobs`.
 */
it('serializes an account by its identifier, never its attributes', function (): void {
    $user = User::factory()->create();
    $serialized = serialize(new PasswordChanged('users', $user));

    expect($serialized)->not->toContain((string) $user->getAttribute('password'))
        ->not->toContain($user->email);

    $copy = unserialize($serialized);

    expect($copy)->toBeInstanceOf(PasswordChanged::class)
        ->and($copy->account->getKey())->toBe($user->getKey())
        ->and($copy->guard)->toBe('users');
});

it('serializes an invitation by its identifier', function (): void {
    $invitation = Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com', ['role' => 'vet'], send: false))->invitation;
    $serialized = serialize(new InvitationCreated('users', $invitation));

    expect($serialized)->not->toContain('invitee@example.com')
        ->and(unserialize($serialized)->invitation->getKey())->toBe($invitation->getKey());
});

/**
 * An event that carries who acted, built with that actor.
 */
function eventWithActor(string $class, User $user, ?Model $actor): object
{
    return match ($class) {
        PasskeyRemoved::class => new PasskeyRemoved('users', $user, 5, actor: $actor),
        AccountLocked::class => new AccountLocked('users', $user, CarbonImmutable::now(), actor: $actor),
        AccountDisabled::class => new AccountDisabled('users', $user, 'fraud review', actor: $actor),
        default => new $class('users', $user, actor: $actor),
    };
}

dataset('events with an actor', [PasswordChanged::class, TwoFactorDisabled::class, PasskeyRemoved::class, AccountLocked::class, AccountDisabled::class, AccountEnabled::class, AccountUnlocked::class]);

it('serializes the actor by its identifier and restores it', function (string $class): void {
    $user = User::factory()->create();
    $actor = Operator::factory()->create();
    $serialized = serialize(eventWithActor($class, $user, $actor));

    expect($serialized)->not->toContain($actor->email)
        ->not->toContain((string) $actor->getRawOriginal('password'));

    $copy = unserialize($serialized);

    expect($copy)->toBeInstanceOf($class)
        ->and($copy->actor)->toBeInstanceOf(Operator::class)
        ->and($copy->actor->is($actor))->toBeTrue()
        ->and($copy->account->is($user))->toBeTrue()
        ->and(unserialize(serialize(eventWithActor($class, $user, null)))->actor)->toBeNull();
})->with('events with an actor');

it('uses SerializesModels on every event that carries a model', function (): void {
    $carriers = [];

    foreach (glob(__DIR__.'/../../../src/Events/*.php') ?: [] as $file) {
        $class = 'RoundlyConsulting\Auth\Events\\'.basename($file, '.php');
        $parameters = (new ReflectionClass($class))->getConstructor()?->getParameters() ?? [];

        foreach ($parameters as $parameter) {
            $type = $parameter->getType();
            $name = $type instanceof ReflectionNamedType ? $type->getName() : null;

            if ($name !== null && (is_a($name, Model::class, true) || $name === Account::class || is_a($name, Invitation::class, true))) {
                $carriers[] = $class;

                expect(in_array(SerializesModels::class, class_uses($class), true))->toBeTrue($class);

                break;
            }
        }
    }

    // Pinned, so the sweep cannot pass over an empty set.
    expect($carriers)->toHaveCount(39);
});
