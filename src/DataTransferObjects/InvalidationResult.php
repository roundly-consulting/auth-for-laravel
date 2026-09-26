<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\InvalidationScope;

/**
 * What an invalidation did: the scope applied, how many sessions it revoked, and — for
 * `others` with a kept device — the pair re-issued to that device, which the client
 * must swap to immediately.
 */
final readonly class InvalidationResult
{
    public function __construct(
        public InvalidationScope $scope,
        public int $revoked = 0,
        public ?TokenPair $tokens = null,
    ) {}
}
