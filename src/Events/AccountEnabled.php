<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A disabled account was enabled again.
 */
final readonly class AccountEnabled
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
