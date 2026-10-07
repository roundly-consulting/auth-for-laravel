<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An email change was requested and a confirmation link went to the new address. It does
 * NOT fire when the new address is already taken (no link is issued), so it is server-side
 * only — never surface it to the requester, or it reveals whether the address is in use.
 */
final readonly class EmailChangeRequested
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public string $newEmail,
    ) {}
}
