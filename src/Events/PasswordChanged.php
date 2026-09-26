<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A password was changed (or set by the host/an admin).
 */
final readonly class PasswordChanged
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
