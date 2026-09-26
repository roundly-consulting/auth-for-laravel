<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use Illuminate\Support\Str;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LogoutScope;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Exceptions\SessionNotFound;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;

/**
 * Ends one of the account's sessions by id. Unknown, malformed and foreign ids are the
 * same 404 — the id is checked to be a uuid before any query (Postgres rejects a
 * malformed uuid literal with a raw query exception).
 */
final readonly class LogoutSession
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, string $sessionId): void
    {
        $this->guards->get($guard);

        if (! Str::isUuid($sessionId)) {
            throw new SessionNotFound;
        }

        if (! RefreshToken::revokeSession(AccountModels::of($account), $sessionId, RevocationReason::Logout)) {
            throw new SessionNotFound;
        }

        event(new LoggedOut($guard, $account, LogoutScope::Session, 1));
    }
}
