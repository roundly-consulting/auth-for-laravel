<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use InvalidArgumentException;

/**
 * Who acted on an account when it was not the account itself (an admin, a support tool),
 * as a reference — morph type and key — never the model. It rides in
 * {@see NotificationData}, which the encrypted delivery job serializes, and an admin
 * model's attributes (password hash, two-factor secret) do not belong in the queue store
 * or `failed_jobs`.
 */
final readonly class ActorData
{
    public function __construct(
        public string $type,
        public int|string $id,
    ) {}

    /**
     * @throws InvalidArgumentException for a model that is not saved
     */
    public static function fromModel(Model $model): self
    {
        $key = $model->getKey();

        if (! $model->exists || (! is_int($key) && ! is_string($key))) {
            throw new InvalidArgumentException('The actor must be a saved model.');
        }

        return new self($model->getMorphClass(), $key);
    }

    /**
     * The same model: its morph type and key (compared as strings, like a morph column).
     */
    public function is(Model $model): bool
    {
        $key = $model->getKey();

        return $this->type === $model->getMorphClass()
            && (is_int($key) || is_string($key))
            && (string) $key === (string) $this->id;
    }

    /**
     * The model, freshly loaded (the morph map applies); null when it no longer exists.
     */
    public function resolve(): ?Model
    {
        $class = Relation::getMorphedModel($this->type) ?? $this->type;

        if (! is_a($class, Model::class, true)) {
            return null;
        }

        return (new $class)->newQuery()->find($this->id);
    }
}
