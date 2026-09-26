<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;

/**
 * One remaining challenge step and the factor methods that can satisfy it.
 */
final readonly class ChallengeRequirement
{
    /**
     * @param  list<FactorMethod>  $methods
     */
    public function __construct(
        public ChallengeStep $step,
        public array $methods,
    ) {}

    public function allows(FactorMethod $method): bool
    {
        return in_array($method, $this->methods, true);
    }

    /**
     * The stored JSON form (a `jsonb` column payload).
     *
     * @return array{step: string, methods: list<string>}
     */
    public function toStorage(): array
    {
        return [
            'step' => $this->step->value,
            'methods' => array_map(static fn (FactorMethod $method): string => $method->value, $this->methods),
        ];
    }

    public static function fromStorage(mixed $stored): ?self
    {
        if (! is_array($stored) || ! is_string($stored['step'] ?? null)) {
            return null;
        }

        $step = ChallengeStep::tryFrom($stored['step']);

        if ($step === null) {
            return null;
        }

        $methods = [];

        foreach (is_array($stored['methods'] ?? null) ? $stored['methods'] : [] as $value) {
            $method = is_string($value) ? FactorMethod::tryFrom($value) : null;

            if ($method !== null) {
                $methods[] = $method;
            }
        }

        return new self($step, $methods);
    }
}
