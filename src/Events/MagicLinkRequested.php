<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A magic link was sent to a real account.
 */
final readonly class MagicLinkRequested
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
