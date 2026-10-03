<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use SensitiveParameter;

/**
 * Bridges refresh-token revocation to the jwt denylist: whenever a session (family)
 * is revoked, the access token minted alongside it (`access_reference` = its jti) is
 * denied until it could no longer be valid anyway — the longest access TTL of any
 * guard plus the verifier's leeway. A singleton, so the (scoped) guard registry is
 * resolved per call from the active container — never captured from the first one.
 */
final class JwtAccessTokenRevoker implements AccessTokenRevoker
{
    public function revoke(#[SensitiveParameter] string $accessReference): void
    {
        if ($accessReference === '') {
            return;
        }

        Jwt::denylist()->deny($accessReference, CarbonImmutable::now()->addSeconds($this->horizon()));
    }

    private function horizon(): int
    {
        // jwt-for-laravel's own settings, read as strictly as jwt reads them.
        $default = Config::integer('jwt.ttl', 900, min: 1);
        $longest = $default;

        foreach (Container::getInstance()->make(GuardRegistry::class)->all() as $guard) {
            $longest = max($longest, $guard->accessTtl() ?? $default);
        }

        return $longest + Config::integer('jwt.leeway', 10, min: 0);
    }
}
