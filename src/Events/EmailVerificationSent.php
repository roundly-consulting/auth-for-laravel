<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A verification link/code was sent.
 */
final readonly class EmailVerificationSent
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
