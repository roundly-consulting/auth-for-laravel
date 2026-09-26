<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A passkey was removed from an account.
 */
final readonly class PasskeyRemoved
{
    public function __construct(
        public string $guard,
        public Account $account,
        public int $passkeyId,
    ) {}
}
