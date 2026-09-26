<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A password hash was upgraded to the current hashing parameters on login.
 */
final readonly class PasswordRehashed
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
