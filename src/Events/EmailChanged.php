<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An email change was confirmed.
 */
final readonly class EmailChanged
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public string $oldEmail,
        public string $newEmail,
    ) {}
}
