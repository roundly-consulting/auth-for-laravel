<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A refresh token was rotated into a new pair.
 */
final readonly class TokensRefreshed
{
    public function __construct(
        public string $guard,
        public Account $account,
        public string $sessionId,
        public string $jti,
    ) {}
}
