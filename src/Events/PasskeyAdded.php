<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A passkey was registered for an account.
 */
final readonly class PasskeyAdded
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public int $passkeyId,
    ) {}
}
