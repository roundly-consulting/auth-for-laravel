<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A password reset link was sent (never fired for unknown addresses).
 */
final readonly class PasswordResetRequested
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
    ) {}
}
