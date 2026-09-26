<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

/**
 * A login-activity row was written — the enrichment hook (ids only).
 */
final readonly class LoginActivityRecorded
{
    public function __construct(
        public int $activityId,
        public string $guard,
    ) {}
}
