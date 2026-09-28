<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Events\ChallengeFailed;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Counts a failed step atomically (`attempts = attempts + 1 WHERE attempts < max AND
 * still active`), invalidates the challenge at the cap, and returns the attempts left.
 *
 * @internal a challenge-engine step; drive challenges through `challenges()`.
 */
final readonly class RecordChallengeFailure
{
    public function __construct(private RecordLoginActivity $recordActivity) {}

    public function execute(LoginChallenge $challenge, ActivityOutcome $outcome, SessionContext $context, ?string $method = null): int
    {
        $now = CarbonImmutable::now();

        Models::challenges()
            ->whereKey($challenge->getKey())
            ->where('attempts', '<', $challenge->max_attempts)
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->increment('attempts');

        $fresh = Models::challenges()->whereKey($challenge->getKey())->first() ?? $challenge;
        $left = $fresh->attemptsLeft();

        if ($left === 0 && $fresh->invalidated_at === null && $fresh->completed_at === null) {
            Models::challenges()
                ->whereKey($challenge->getKey())
                ->whereNull('invalidated_at')
                ->update(['invalidated_at' => $now, 'invalidated_reason' => 'attempts_exhausted']);
        }

        $account = $challenge->account;
        $account = $account instanceof Account ? $account : null;

        $this->recordActivity->execute(new LoginActivityData(
            guard: $challenge->guard,
            type: ActivityType::ChallengeStep,
            outcome: $outcome,
            context: $context,
            method: $method,
            reason: $left === 0 ? 'attempts_exhausted' : $outcome->value,
            account: $account,
            challengeId: (int) $challenge->getKey(),
        ));

        event(new ChallengeFailed($challenge->guard, $account, $outcome));

        return $left;
    }
}
