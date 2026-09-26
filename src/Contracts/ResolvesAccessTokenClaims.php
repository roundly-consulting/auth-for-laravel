<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use RoundlyConsulting\Auth\DataTransferObjects\AccessTokenClaims;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Per-guard `tokens.claims_resolver`: what the host puts into an access token
 * (email, permissions, extra claims).
 */
interface ResolvesAccessTokenClaims
{
    public function resolve(Account $account, GuardConfig $guard): AccessTokenClaims;
}
