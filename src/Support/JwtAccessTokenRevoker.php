<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use SensitiveParameter;

/**
 * Bridges refresh-token revocation to the jwt denylist: whenever a session (family)
 * is revoked, the access token minted alongside it (`access_reference` = its jti) is
 * denied until it could no longer be valid anyway — the longest access TTL of any
 * guard plus the verifier's leeway.
 */
final class JwtAccessTokenRevoker implements AccessTokenRevoker
{
    public function __construct(private readonly GuardRegistry $guards) {}

    public function revoke(#[SensitiveParameter] string $accessReference): void
    {
        if ($accessReference === '') {
            return;
        }

        Jwt::denylist()->deny($accessReference, CarbonImmutable::now()->addSeconds($this->horizon()));
    }

    private function horizon(): int
    {
        $default = (int) config('jwt.ttl', 900);
        $longest = $default;

        foreach ($this->guards->all() as $guard) {
            $longest = max($longest, $guard->accessTtl() ?? $default);
        }

        return $longest + max(0, (int) config('jwt.leeway', 0));
    }
}
