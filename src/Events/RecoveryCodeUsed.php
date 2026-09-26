<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A recovery code satisfied a second factor.
 */
final readonly class RecoveryCodeUsed
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public int $remaining,
    ) {}
}
