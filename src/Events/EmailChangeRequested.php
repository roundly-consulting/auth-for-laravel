<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An email change was requested; the new address must confirm it.
 */
final readonly class EmailChangeRequested
{
    public function __construct(
        public string $guard,
        public Account $account,
        public string $newEmail,
    ) {}
}
