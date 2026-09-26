<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\LoginMethod;

/**
 * A login attempt failed. `account` is set only when the attempt identified one — for listeners, never the response.
 */
final readonly class LoginFailed
{
    public function __construct(
        public string $guard,
        public ?Account $account,
        public LoginMethod $method,
        public ActivityOutcome $outcome,
        public ?string $reason,
        public SessionContext $context,
    ) {}
}
