<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Tokens;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use RoundlyConsulting\Auth\Actions\Sessions\EnforceSessionLimit;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;

/**
 * Starts a new session: an access token and the root of a new refresh-token family.
 *
 * The chicken-and-egg (the access token carries the session id; the refresh token
 * carries the access token's jti) is solved by choosing the session id first: it is
 * minted into `sid`, then used as the refresh family's root id.
 */
final readonly class IssueTokenPair
{
    public function __construct(
        private BuildAccessTokenRequest $buildRequest,
        private EnforceSessionLimit $enforceSessionLimit,
    ) {}

    /**
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function execute(
        GuardConfig $guard,
        Account $account,
        LoginMethod $method,
        array $authMethods,
        SessionContext $context,
        ?CarbonImmutable $authTime = null,
    ): TokenPair {
        (new AccountRepository($guard))->ensureOwns($account);

        $authTime ??= CarbonImmutable::now();
        $sessionId = (string) Str::uuid();

        $access = Jwt::mintAccessToken($this->buildRequest->execute($guard, $account, $sessionId, $authMethods, $authTime));

        $refresh = RefreshToken::issue(AccountModels::of($account), new IssueContext(
            ipAddress: $context->ipAddress,
            userAgent: $context->userAgent,
            accessReference: $access->jti,
            newFamilyId: $sessionId,
            ttl: $guard->refreshTtl(),
            absoluteTtl: $guard->refreshAbsoluteTtl(),
            meta: [
                'guard' => $guard->name(),
                'method' => $method->value,
                'amr' => AuthMethodReference::toValues($authMethods),
                'auth_time' => $authTime->getTimestamp(),
                'device_name' => $context->deviceName,
            ],
        ));

        $this->enforceSessionLimit->execute($guard, $account);

        return new TokenPair(
            accessToken: $access->token,
            accessExpiresAt: $access->expiresAt,
            refreshToken: $refresh->plainText,
            refreshExpiresAt: $refresh->token->expires_at,
            sessionId: $sessionId,
            accessTokenId: $access->jti,
        );
    }
}
