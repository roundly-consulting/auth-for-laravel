<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account's recovery codes were replaced.
 */
final readonly class RecoveryCodesRegenerated
{
    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
