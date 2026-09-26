<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LoginMethod;

/**
 * A token pair was issued (login, challenge completion, host issue, credential-change re-issue).
 */
final readonly class TokensIssued
{
    public function __construct(
        public string $guard,
        public Account $account,
        public string $sessionId,
        public string $jti,
        public LoginMethod $method,
    ) {}
}
