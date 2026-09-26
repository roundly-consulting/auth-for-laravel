<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ThrottleKind;

/**
 * A rate limit was hit.
 */
final readonly class LoginThrottled
{
    public function __construct(
        public string $guard,
        public ThrottleKind $kind,
        public int $retryAfter,
        public SessionContext $context,
    ) {}
}
