<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Relations\Relation;
use RoundlyConsulting\Auth\DataTransferObjects\ActorData;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Operator;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('references a model by its morph type and key only', function (): void {
    $user = User::factory()->create();
    $actor = ActorData::fromModel($user);

    expect($actor->type)->toBe(User::class)
        ->and($actor->id)->toBe($user->getKey())
        ->and(get_object_vars($actor))->toBe(['type' => User::class, 'id' => $user->getKey()]);
});

it('is the same model, and not another id or another type with the same id', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $client = Client::factory()->create(['id' => $user->getKey()]);
    $actor = ActorData::fromModel($user);

    expect($actor->is($user))->toBeTrue()
        ->and($actor->is(User::query()->findOrFail($user->getKey())))->toBeTrue()
        ->and($actor->is($other))->toBeFalse()
        ->and($actor->is($client))->toBeFalse()
        ->and(ActorData::fromModel($client)->is($user))->toBeFalse()
        ->and((new ActorData(User::class, (string) $user->getKey()))->is($user))->toBeTrue();
});

it('resolves the model it references, honouring the morph map', function (): void {
    $previous = Relation::morphMap();
    Relation::morphMap(['operator' => Operator::class]);

    try {
        $operator = Operator::factory()->create();
        $actor = ActorData::fromModel($operator);

        expect($actor->type)->toBe('operator')
            ->and($actor->resolve())->toBeInstanceOf(Operator::class)
            ->and($actor->resolve()?->is($operator))->toBeTrue()
            ->and($actor->is($operator))->toBeTrue();
    } finally {
        Relation::morphMap($previous, false);
    }
});

it('resolves nothing for a deleted model or a type that is no model', function (): void {
    $operator = Operator::factory()->create();
    $actor = ActorData::fromModel($operator);
    $operator->delete();

    expect($actor->resolve())->toBeNull()
        ->and((new ActorData('not-a-model', 1))->resolve())->toBeNull()
        ->and((new ActorData(stdClass::class, 1))->resolve())->toBeNull();
});

it('refuses a model without a key', function (): void {
    expect(fn () => ActorData::fromModel(new Operator))->toThrow(InvalidArgumentException::class, 'The actor must be a saved model.');
});
