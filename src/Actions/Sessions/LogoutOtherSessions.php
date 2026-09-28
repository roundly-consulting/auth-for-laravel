<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\LogoutScope;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

/**
 * Ends every session but the caller's. No `tv` bump (that would log the caller out
 * too): each revoked family's live access token is denied by the revoker; an older
 * token of another family lives at most `access_ttl` — use logout-everywhere to close
 * that gap.
 */
final readonly class LogoutOtherSessions
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, CurrentToken $current): int
    {
        $this->guards->owning($guard, $account);

        $revoked = RefreshTokens::sessions(AccountModels::of($account))->revokeAllExcept($current->sessionId, RevocationReason::LogoutAll);

        event(new LoggedOut($guard, $account, LogoutScope::Others, $revoked));

        return $revoked;
    }
}
