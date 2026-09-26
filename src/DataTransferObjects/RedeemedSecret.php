<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Models\OneTimeToken;

/**
 * A one-time secret that was just claimed, with the (still active) account it belongs to.
 */
final readonly class RedeemedSecret
{
    public function __construct(
        public OneTimeToken $record,
        public Account $account,
    ) {}
}
