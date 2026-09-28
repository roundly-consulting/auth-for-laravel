<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Tokens;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\ResolvesAccessTokenClaims;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\DefaultClaimsResolver;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;

/**
 * Builds the access-token request for an account: the guard's own audience (the
 * isolation boundary), `sub`, `tv`, the session claims (`sid`, `amr`, `auth_time`), the
 * guard name (`grd`, diagnostics) and the host's claims.
 *
 * @internal a token-issuing step (`IssueTokenPair`, `RefreshTokenPair`).
 */
final readonly class BuildAccessTokenRequest
{
    public function __construct(private Container $container) {}

    /**
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function execute(GuardConfig $guard, Account $account, string $sessionId, array $authMethods, CarbonImmutable $authTime): AccessTokenRequest
    {
        $claims = $this->resolver($guard)->resolve($account, $guard);
        $identifier = $account->getAuthIdentifier();

        $request = AccessTokenRequest::for(is_int($identifier) || is_string($identifier) ? $identifier : (string) $identifier)
            ->audience(Jwt::guard($guard->laravelGuard())->audience())
            ->tokenVersion($account->tokenVersion())
            ->sessionId($sessionId)
            ->authTime($authTime)
            ->withClaims([...$claims->extra, 'grd' => $guard->name()]);

        if ($claims->email !== null) {
            $request = $request->email($claims->email, $claims->emailVerified);
        }

        if ($claims->permissions !== []) {
            $request = $request->permissions(...$claims->permissions);
        }

        if ($authMethods !== []) {
            $request = $request->authMethods(...AuthMethodReference::toValues($authMethods));
        }

        $ttl = $guard->accessTtl();

        return $ttl === null ? $request : $request->ttl($ttl);
    }

    private function resolver(GuardConfig $guard): ResolvesAccessTokenClaims
    {
        $class = $guard->claimsResolver() ?? DefaultClaimsResolver::class;
        $resolver = $this->container->make($class);

        return $resolver instanceof ResolvesAccessTokenClaims ? $resolver : $this->container->make(DefaultClaimsResolver::class);
    }
}
