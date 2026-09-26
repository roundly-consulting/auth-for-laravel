<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A disabled account was enabled again.
 */
final readonly class AccountEnabled
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
