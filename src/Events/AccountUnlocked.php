<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A locked account was unlocked.
 */
final readonly class AccountUnlocked
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
