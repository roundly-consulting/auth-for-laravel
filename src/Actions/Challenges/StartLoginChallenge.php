<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\PendingLogin;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\ChallengeFingerprint;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * Opens a pending challenge: an opaque 64-char token (only its HMAC stored), the steps
 * still required, a snapshot of the account's token version (any invalidation before
 * the challenge finalizes kills it), and the device fingerprint. At most
 * `challenge.max_active_per_account` stay active — older ones are superseded, so a
 * password-holding attacker cannot farm parallel challenges for extra guesses.
 */
final readonly class StartLoginChallenge
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
        private ChallengeFingerprint $fingerprint,
    ) {}

    /**
     * @param  list<ChallengeRequirement>  $requirements
     */
    public function execute(PendingLogin $login, array $requirements): PendingChallenge
    {
        $guard = $this->guards->get($login->guard);
        $account = AccountModels::of($login->account);
        $now = CarbonImmutable::now();

        $this->supersedeOlder($login->guard, $account->getMorphClass(), $account->getKey(), $guard->maxActiveChallenges(), $now);

        $enrols = array_filter($requirements, static fn (ChallengeRequirement $requirement): bool => $requirement->step->isEnrolment()) !== [];
        $expiresAt = $now->addSeconds($enrols ? $guard->challengeEnrolmentTtl() : $guard->challengeTtl());
        $token = Token::urlSafe(64);

        $challenge = Models::challenges()->create([
            'guard' => $guard->name(),
            'account_type' => $account->getMorphClass(),
            'account_id' => $account->getKey(),
            'token_hash' => $this->hasher->link($guard->name(), 'challenge', $token),
            'method' => $login->method,
            'required_steps' => array_map(static fn (ChallengeRequirement $requirement): array => $requirement->toStorage(), $requirements),
            'completed_steps' => [],
            'context' => [
                'amr' => AuthMethodReference::toValues($login->authMethods),
                'auth_time' => $login->authTime->getTimestamp(),
                'token_version' => $login->account->tokenVersion(),
                'new_device' => $login->newDevice,
                'risk_level' => $login->riskLevel->value,
                'notify_risk' => $login->notifyRisk,
                'identifier' => $login->identifier,
            ],
            'fingerprint_hash' => $this->fingerprint->for($guard, $login->context),
            'ip_address' => $login->context->ipAddress,
            'user_agent' => $login->context->userAgent,
            'attempts' => 0,
            'max_attempts' => $guard->challengeMaxAttempts(),
            'version' => 0,
            'expires_at' => $expiresAt,
        ]);

        return new PendingChallenge(
            token: $token,
            expiresAt: $expiresAt,
            method: $login->method,
            completed: [],
            remaining: $requirements,
            attemptsLeft: $guard->challengeMaxAttempts(),
            challengeId: (int) $challenge->getKey(),
        );
    }

    private function supersedeOlder(string $guard, string $accountType, mixed $accountId, int $maxActive, CarbonImmutable $now): void
    {
        $active = Models::challenges()
            ->forGuard($guard)
            ->where('account_type', $accountType)
            ->where('account_id', $accountId)
            ->active($now)
            ->orderByDesc('id')
            ->pluck('id')
            ->all();

        $stale = array_slice($active, max(0, $maxActive - 1));

        if ($stale !== []) {
            Models::challenges()->whereKey($stale)->update(['invalidated_at' => $now, 'invalidated_reason' => 'superseded']);
        }
    }
}
