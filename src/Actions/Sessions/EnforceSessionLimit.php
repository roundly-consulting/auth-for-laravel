<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LogoutScope;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;

/**
 * Applies `sessions.max_active`: the oldest sessions above the cap are revoked.
 */
final class EnforceSessionLimit
{
    public function execute(GuardConfig $guard, Account $account): int
    {
        $max = $guard->maxActiveSessions();

        if ($max === null) {
            return 0;
        }

        $model = AccountModels::of($account);
        $revoked = 0;

        foreach (RefreshToken::listFor($model)->slice($max) as $session) {
            if (RefreshToken::revokeSession($model, $session->family_id, RevocationReason::SessionLimit)) {
                $revoked++;
            }
        }

        if ($revoked > 0) {
            event(new LoggedOut($guard->name(), $account, LogoutScope::Session, $revoked));
        }

        return $revoked;
    }
}
