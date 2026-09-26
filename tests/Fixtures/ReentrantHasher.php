<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures;

use Closure;
use Illuminate\Contracts\Hashing\Hasher;
use SensitiveParameter;

/**
 * Stands in for concurrency: every password check first runs `$concurrent` — another
 * request arriving while this one is still hashing — until `$burst` checks happened.
 */
final class ReentrantHasher implements Hasher
{
    public int $checks = 0;

    /**
     * @param  Closure(int): void  $concurrent
     */
    public function __construct(
        private readonly Hasher $inner,
        private readonly Closure $concurrent,
        private readonly int $burst,
    ) {}

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
        $this->checks++;

        if ($this->checks < $this->burst) {
            ($this->concurrent)($this->checks);
        }

        return $this->inner->check($value, $hashedValue, $options);
    }

    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->inner->needsRehash($hashedValue, $options);
    }
}
