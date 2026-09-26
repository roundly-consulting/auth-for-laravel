<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account was hard-locked (opt-in lockout, or an admin).
 */
final readonly class AccountLocked
{
    public function __construct(
        public string $guard,
        public Account $account,
        public CarbonImmutable $until,
    ) {}
}
