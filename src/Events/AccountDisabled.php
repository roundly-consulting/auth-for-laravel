<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account was disabled.
 */
final readonly class AccountDisabled
{
    public function __construct(
        public string $guard,
        public Account $account,
        public ?string $reason,
    ) {}
}
