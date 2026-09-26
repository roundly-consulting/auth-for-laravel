<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An email change was confirmed.
 */
final readonly class EmailChanged
{
    public function __construct(
        public string $guard,
        public Account $account,
        public string $oldEmail,
        public string $newEmail,
    ) {}
}
