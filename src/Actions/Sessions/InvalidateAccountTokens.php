<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\InvalidateOneTimeTokens;
use RoundlyConsulting\Auth\Actions\Tokens\IssueTokenPair;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\InvalidationResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Events\AccountTokensInvalidated;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;

/**
 * The invalidation policy applied after every credential change or incident, per the
 * guard's `invalidation.<reason>` scope:
 *
 *  - `none`   — nothing (credential one-time tokens — sign-in links and codes,
 *               resets, re-authentication codes, pending email changes — still die
 *               for resets, disables and email changes);
 *  - `others` — `tv++`, every family revoked, then a fresh pair issued for the kept
 *               (calling) device with the same `amr`/`auth_time` — returned, because
 *               otherwise the device making the change is logged out by its own bump.
 *               Without a kept device it behaves as `all`;
 *  - `all`    — `tv++` and every family revoked.
 *
 * Any scope but `none` also kills the account's pending challenges (except the one
 * whose enrolment step triggered this) and its credential one-time tokens. The DB writes run
 * in one transaction; the denylist writes are cache-backed and not transactional — a
 * rollback leaves an over-denied jti, which is harmless.
 */
final readonly class InvalidateAccountTokens
{
    public function __construct(
        private IssueTokenPair $issueTokenPair,
        private InvalidateOneTimeTokens $invalidateOneTimeTokens,
    ) {}

    public function execute(
        GuardConfig $guard,
        Account $account,
        InvalidationReason $reason,
        ?CurrentToken $keep,
        SessionContext $context,
        ?int $exceptChallengeId = null,
    ): InvalidationResult {
        (new AccountRepository($guard))->ensureOwns($account);

        $scope = $guard->invalidationScope($reason);

        if ($scope === InvalidationScope::None) {
            if ($reason->alwaysInvalidatesOneTimeTokens()) {
                $this->invalidateOneTimeTokens->execute($guard->name(), $account, ...OneTimeTokenPurpose::credentialPurposes());
            }

            return new InvalidationResult($scope);
        }

        $model = AccountModels::of($account);
        $kept = $scope === InvalidationScope::Others && $keep?->sessionId !== null
            ? RefreshToken::findSession($model, $keep->sessionId)
            : null;
        $meta = $kept === null ? [] : ($kept->meta ?? []);

        $revoked = $model->getConnection()->transaction(function () use ($guard, $account, $model, $reason, $exceptChallengeId): int {
            AccountState::bumpTokenVersion($account);

            $revoked = RefreshToken::revokeAll($model, $reason->revocationReason());

            Models::challenges()
                ->forGuard($guard->name())
                ->where('account_type', $model->getMorphClass())
                ->where('account_id', $model->getKey())
                ->active()
                ->when($exceptChallengeId !== null, static fn ($query) => $query->whereKeyNot($exceptChallengeId))
                ->update(['invalidated_at' => CarbonImmutable::now(), 'invalidated_reason' => 'superseded']);

            $this->invalidateOneTimeTokens->execute($guard->name(), $account, ...OneTimeTokenPurpose::credentialPurposes());

            return $revoked;
        });

        if ($keep !== null) {
            Jwt::denylist()->deny($keep->jti, $keep->expiresAt);
        }

        $tokens = null;

        if ($kept !== null) {
            $method = LoginMethod::tryFrom(is_string($meta['method'] ?? null) ? $meta['method'] : '') ?? LoginMethod::Host;
            $authTime = is_int($meta['auth_time'] ?? null) ? CarbonImmutable::createFromTimestamp($meta['auth_time']) : $kept->sessionStartedAt();

            $tokens = $this->issueTokenPair->execute(
                $guard,
                $account,
                $method,
                AuthMethodReference::fromValues($meta['amr'] ?? null),
                $context,
                $authTime,
            );

            event(new TokensIssued($guard->name(), $account, $tokens->sessionId, $tokens->accessTokenId, $method));
        }

        $applied = $kept !== null ? InvalidationScope::Others : InvalidationScope::All;

        event(new AccountTokensInvalidated($guard->name(), $account, $reason, $applied, $revoked));

        return new InvalidationResult($applied, $revoked, $tokens);
    }
}
