<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * TOTP two-factor authentication was confirmed for an account.
 */
final readonly class TwoFactorEnabled
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
