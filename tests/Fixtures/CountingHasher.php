<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures;

use Illuminate\Contracts\Hashing\Hasher;
use SensitiveParameter;

/**
 * Wraps the real hasher and records every hash a password was checked against.
 */
final class CountingHasher implements Hasher
{
    /** @var list<string> */
    public array $checked = [];

    public function __construct(private readonly Hasher $inner) {}

    public function info($hashedValue): array
    {
        return $this->inner->info($hashedValue);
    }

    public function make(#[SensitiveParameter] $value, array $options = []): string
    {
        return $this->inner->make($value, $options);
    }

    public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
    {
        $this->checked[] = (string) $hashedValue;

        return $this->inner->check($value, $hashedValue, $options);
    }

    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->inner->needsRehash($hashedValue, $options);
    }
}
