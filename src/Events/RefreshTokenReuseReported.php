<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * refresh-tokens-for-laravel detected reuse of a rotated token; re-emitted with the guard and account resolved.
 */
final readonly class RefreshTokenReuseReported
{
    public function __construct(
        public string $guard,
        public Account $account,
        public string $sessionId,
    ) {}
}
