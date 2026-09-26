<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An email login code was sent to a real account.
 */
final readonly class EmailOtpRequested
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
