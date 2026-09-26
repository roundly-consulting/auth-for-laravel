<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A password was changed (or set by the host/an admin).
 */
final readonly class PasswordChanged
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
