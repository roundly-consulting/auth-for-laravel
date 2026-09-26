<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures;

use Illuminate\Contracts\Hashing\Hasher;
use SensitiveParameter;

/**
 * Wraps the real hasher and records every hash a password was checked against, and how
 * many hashes were made. Swapped in for the `hash` manager, so it is its own driver.
 */
final class CountingHasher implements Hasher
{
    /** @var list<string> */
    public array $checked = [];

    public int $made = 0;

    public function __construct(private readonly Hasher $inner) {}

    public function info($hashedValue): array
    {
        return $this->inner->info($hashedValue);
    }

    public function make(#[SensitiveParameter] $value, array $options = []): string
    {
        $this->made++;

        return $this->inner->make($value, $options);
    }

    public function driver(?string $name = null): self
    {
        return $this;
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
