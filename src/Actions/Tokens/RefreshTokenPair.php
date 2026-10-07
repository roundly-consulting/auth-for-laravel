<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Tokens;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\TokensRefreshed;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use SensitiveParameter;

/**
 * Rotates a refresh token into a new pair within the same session.
 *
 * The redeem is scoped to this guard's owner morph class, so a token of another guard
 * is "unknown" and is NOT consumed. `redeem()` + `issue(familyId)` is used rather than
 * `rotate()`: the replacement's access reference must be the jti minted AFTER the
 * redeem. `amr`/`auth_time`/device data are inherited from the family's newest row.
 * Only failures are recorded as activity (volume).
 *
 * A family minted under an older `token_version` than the account's is revoked and
 * refused: the login that opened it raced an invalidation (it loaded the account, the
 * invalidation bumped the version and revoked every family, then the login opened this
 * one), so no session survives a password reset, a disable or a logout everywhere.
 *
 * The family can die between the redeem and the issue — reuse detection, a logout,
 * a credential change or a disable landing concurrently. refresh-tokens then refuses to
 * extend it (or hands back an already-revoked row); either way the access token just
 * minted is denied and the answer is a plain 401, never a 500 or a live session.
 *
 * A successful refresh retires the access token minted with the redeemed refresh token:
 * a session holds exactly one live access token, so revoking it (logout, logout others,
 * the session cap, reuse detection) kills every token the session ever minted — not just
 * the newest one while a copied older one lives on until it expires.
 */
final readonly class RefreshTokenPair
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private BuildAccessTokenRequest $buildRequest,
        private RecordLoginActivity $recordActivity,
        private AccessTokenRevoker $revoker,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $refreshToken, SessionContext $context): TokenPair
    {
        $config = $this->guards->get($guard);
        $accounts = new AccountRepository($config);

        $this->throttle->attempt($config, [ThrottleKind::Refresh], null, $context, ActivityType::Refresh);

        $redeemed = RefreshTokens::redeem($refreshToken, $accounts->morphClass());
        $owner = $redeemed?->user;

        if ($redeemed === null || ! $owner instanceof Account) {
            $this->fail($guard, $context, null, 'unknown');
        }

        if ($owner->isDisabled()) {
            RefreshTokens::sessions($redeemed->user)->revoke($redeemed->familyId, RevocationReason::AccountDisabled);
            $this->fail($guard, $context, $owner, 'disabled');
        }

        $meta = $redeemed->redeemedToken->meta ?? [];

        // A login that loaded the account before an invalidation bumped `tv` and revoked every
        // family opens its family after that revoke: the stale version it was minted under is
        // what still marks it. Families issued before `tv` was recorded carry none.
        if (is_int($meta['tv'] ?? null) && $meta['tv'] !== $owner->tokenVersion()) {
            RefreshTokens::sessions($redeemed->user)->revoke($redeemed->familyId, RevocationReason::Security);
            $this->fail($guard, $context, $owner, 'revoked');
        }
        // A session without a recorded auth_time (issued by host code) was authenticated
        // when it started — never "just now", which would pass every fresh-login gate.
        $authTime = is_int($meta['auth_time'] ?? null) ? CarbonImmutable::createFromTimestamp($meta['auth_time']) : $redeemed->redeemedToken->sessionStartedAt();

        $access = Jwt::mintAccessToken($this->buildRequest->execute(
            $config,
            $owner,
            $redeemed->familyId,
            AuthMethodReference::fromValues($meta['amr'] ?? null),
            $authTime,
        ));

        try {
            $replacement = RefreshTokens::issue($redeemed->user, new IssueContext(
                ipAddress: $context->ipAddress,
                userAgent: $context->userAgent,
                accessReference: $access->jti,
                familyId: $redeemed->familyId,
                ttl: $config->refreshTtl(),
            ));
        } catch (InvalidTokenFamilyException) {
            $replacement = null;
        }

        if ($replacement === null || $replacement->token->revoked_at !== null) {
            Jwt::denylist()->deny($access->jti, $access->expiresAt);
            $this->fail($guard, $context, $owner, 'revoked');
        }

        $previous = $redeemed->redeemedToken->access_reference;

        if ($previous !== null && $previous !== '') {
            $this->revoker->revoke($previous);
        }

        event(new TokensRefreshed($guard, $owner, $redeemed->familyId, $access->jti));

        return new TokenPair(
            accessToken: $access->token,
            accessExpiresAt: $access->expiresAt,
            refreshToken: $replacement->plainText,
            refreshExpiresAt: $replacement->token->expires_at,
            sessionId: $redeemed->familyId,
            accessTokenId: $access->jti,
        );
    }

    private function fail(string $guard, SessionContext $context, ?Account $account, string $reason): never
    {
        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::Refresh,
            outcome: ActivityOutcome::FailedToken,
            context: $context,
            reason: $reason,
            account: $account,
        ));

        throw new InvalidRefreshToken;
    }
}
