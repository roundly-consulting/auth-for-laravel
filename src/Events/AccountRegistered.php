<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LoginMethod;

/**
 * An account was created through registration or an invitation. Hosts hang side effects (statistics, roles) here.
 */
final readonly class AccountRegistered
{
    public function __construct(
        public string $guard,
        public Account $account,
        public LoginMethod $via,
    ) {}
}
