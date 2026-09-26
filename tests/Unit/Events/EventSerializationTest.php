<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\Events\InvitationCreated;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\Invitation;
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
    $invitation = Authentication::guard('users')->invite(new InvitationData('invitee@example.com', ['role' => 'vet'], send: false));
    $serialized = serialize(new InvitationCreated('users', $invitation));

    expect($serialized)->not->toContain('invitee@example.com')
        ->and(unserialize($serialized)->invitation->getKey())->toBe($invitation->getKey());
});

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
