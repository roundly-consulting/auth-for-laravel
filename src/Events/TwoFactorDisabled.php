<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * TOTP two-factor authentication was disabled for an account.
 */
final readonly class TwoFactorDisabled
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
