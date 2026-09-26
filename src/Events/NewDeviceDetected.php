<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;

/**
 * A login completed from a device the account had not used before.
 */
final readonly class NewDeviceDetected
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public SessionContext $context,
    ) {}
}
