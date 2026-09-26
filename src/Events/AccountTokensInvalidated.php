<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;

/**
 * An account's tokens were invalidated after a credential change or incident.
 */
final readonly class AccountTokensInvalidated
{
    public function __construct(
        public string $guard,
        public Account $account,
        public InvalidationReason $reason,
        public InvalidationScope $scope,
        public int $revoked,
    ) {}
}
