<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Login\CompleteLogin;
use RoundlyConsulting\Auth\Actions\Login\EnsureAccountCanLogin;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\PendingLogin;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\RiskLevel;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Completes a challenge whose steps are all done: re-checks the account's state (it may
 * have been disabled mid-challenge) and its token version against the snapshot (a
 * password reset, disable or logout-everywhere in between kills the login), then claims
 * the challenge once (`completed_at … WHERE completed_at IS NULL AND version = ?`) — a
 * replayed final step gets nothing — and runs the success tail.
 */
final readonly class FinalizeChallenge
{
    public function __construct(
        private GuardRegistry $guards,
        private EnsureAccountCanLogin $ensureCanLogin,
        private CompleteLogin $completeLogin,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(LoginChallenge $challenge, SessionContext $context): TokenPair
    {
        $guard = $this->guards->get($challenge->guard);
        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        $identifier = $challenge->contextValue('identifier');
        $identifier = is_string($identifier) ? $identifier : null;

        $this->ensureCanLogin->execute($guard, $account, $challenge->method, $context, $identifier);

        $now = CarbonImmutable::now();

        if ((int) $challenge->contextValue('token_version') !== $account->tokenVersion()) {
            Models::challenges()->whereKey($challenge->getKey())->whereNull('invalidated_at')
                ->update(['invalidated_at' => $now, 'invalidated_reason' => 'superseded']);

            throw new ChallengeInvalid;
        }

        $claimed = Models::challenges()
            ->whereKey($challenge->getKey())
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->where('version', $challenge->version)
            ->update(['completed_at' => $now]);

        if ($claimed === 0) {
            $this->recordActivity->execute(new LoginActivityData(
                guard: $guard->name(),
                type: ActivityType::ChallengeStep,
                outcome: ActivityOutcome::Replayed,
                context: $context,
                account: $account,
                challengeId: (int) $challenge->getKey(),
            ));

            throw new ChallengeInvalid;
        }

        $authTime = $challenge->contextValue('auth_time');

        return $this->completeLogin->execute(new PendingLogin(
            guard: $guard->name(),
            account: $account,
            method: $challenge->method,
            // Every challenge adds at least one factor to the first one.
            authMethods: [...$challenge->authMethods(), AuthMethodReference::Mfa],
            authTime: is_int($authTime) ? CarbonImmutable::createFromTimestamp($authTime) : $now,
            context: $context,
            newDevice: (bool) $challenge->contextValue('new_device'),
            riskLevel: RiskLevel::tryFrom((string) $challenge->contextValue('risk_level')) ?? RiskLevel::Low,
            notifyRisk: (bool) $challenge->contextValue('notify_risk'),
            challengeId: (int) $challenge->getKey(),
            identifier: $identifier,
        ));
    }
}
