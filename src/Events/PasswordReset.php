<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A password was reset through an emailed link.
 */
final readonly class PasswordReset
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
