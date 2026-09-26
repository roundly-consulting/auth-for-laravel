<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;

/**
 * How and when a session last re-proved itself — what the re-authentication marker
 * records, so a check can tell a password proof from a second-factor one.
 */
final readonly class ReauthenticationProof
{
    public function __construct(
        public ReauthenticationMethod $method,
        public CarbonImmutable $at,
    ) {}
}
