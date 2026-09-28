<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\LogoutScope;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

/**
 * Ends the calling session: its access token is denied until expiry and its refresh
 * family revoked.
 */
final readonly class LogoutCurrentSession
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, CurrentToken $current): void
    {
        $this->guards->get($guard);

        Jwt::denylist()->deny($current->jti, $current->expiresAt);

        $revoked = $current->sessionId === null
            ? false
            : RefreshTokens::sessions(AccountModels::of($account))->revoke($current->sessionId, RevocationReason::Logout);

        event(new LoggedOut($guard, $account, LogoutScope::Current, $revoked ? 1 : 0));
    }
}
