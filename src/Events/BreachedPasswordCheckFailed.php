<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

/**
 * The breached-password service could not be reached.
 */
final readonly class BreachedPasswordCheckFailed
{
    public function __construct(
        public string $guard,
    ) {}
}
