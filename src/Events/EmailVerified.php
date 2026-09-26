<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An email address was verified.
 */
final readonly class EmailVerified
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
