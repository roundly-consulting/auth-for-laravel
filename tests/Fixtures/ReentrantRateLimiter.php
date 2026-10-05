<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;

/**
 * Stands in for concurrency on a cache key: the first time a key containing `$needle` is
 * incremented, `$concurrent` — another request that has checked the key just as this one
 * did — runs before the increment lands.
 */
final class ReentrantRateLimiter extends RateLimiter
{
    private bool $fired = false;

    public function __construct(
        Repository $cache,
        private readonly string $needle,
        private readonly Closure $concurrent,
    ) {
        parent::__construct($cache);
    }

    public function increment($key, $decaySeconds = 60, $amount = 1)
    {
        if (! $this->fired && str_contains((string) $key, $this->needle)) {
            $this->fired = true;
            ($this->concurrent)();
        }

        return parent::increment($key, $decaySeconds, $amount);
    }
}
