<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\LoginMethod;

/**
 * A login completed and tokens were issued.
 */
final readonly class LoginSucceeded
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public LoginMethod $method,
        public string $sessionId,
        public SessionContext $context,
    ) {}
}
