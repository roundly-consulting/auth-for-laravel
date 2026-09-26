<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\ResolvesAccessTokenClaims;
use RoundlyConsulting\Auth\DataTransferObjects\AccessTokenClaims;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * The default claims: the account's email and its verification state (per
 * `tokens.include_email`), no permissions. Bind your own resolver per guard to add
 * permissions or extra claims.
 */
final class DefaultClaimsResolver implements ResolvesAccessTokenClaims
{
    public function resolve(Account $account, GuardConfig $guard): AccessTokenClaims
    {
        return new AccessTokenClaims(
            email: $guard->includesEmailClaim() ? $account->accountEmail() : null,
            emailVerified: $account->hasVerifiedEmail(),
        );
    }
}
