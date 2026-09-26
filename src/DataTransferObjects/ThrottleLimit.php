<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

final readonly class ThrottleLimit
{
    public function __construct(
        public int $maxAttempts,
        public int $decaySeconds,
    ) {}
}
