<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Events\ChallengeStepCompleted;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\Models;
use SensitiveParameter;

/**
 * Records a satisfied step with an optimistic write (`… WHERE version = ?`): of two
 * concurrent submissions exactly one advances, the other gets {@see ChallengeInvalid}.
 * The caller passes the copy it verified against — never a re-read, which would carry
 * another request's progress past the version check — and the step it verified, which
 * must still be the next one. Finalizes the login when no step remains.
 *
 * @internal a challenge-engine step; drive challenges through `challenges()`.
 */
final readonly class AdvanceChallenge
{
    public function __construct(private FinalizeChallenge $finalize) {}

    /**
     * @param  ChallengeStep  $completes  the step the caller verified; must be the challenge's next one
     * @param  list<AuthMethodReference>  $authMethods  added to the challenge's amr
     * @param  int|null  $tokenVersion  the account's new token version, when this step itself bumped it (enrolment)
     */
    public function execute(
        LoginChallenge $challenge,
        ChallengeStep $completes,
        #[SensitiveParameter] string $token,
        FactorMethod $method,
        array $authMethods,
        SessionContext $context,
        ?int $tokenVersion = null,
    ): LoginResult {
        $remaining = $challenge->remaining();
        $step = array_shift($remaining);

        if ($step === null || $step->step !== $completes) {
            throw new ChallengeInvalid;
        }

        $completed = [...$challenge->completed(), $step->step];

        $stored = $challenge->context ?? [];
        $stored['amr'] = AuthMethodReference::toValues([...$challenge->authMethods(), ...$authMethods]);

        if ($tokenVersion !== null) {
            $stored['token_version'] = $tokenVersion;
        }

        $advanced = Models::challenges()
            ->whereKey($challenge->getKey())
            ->where('version', $challenge->version)
            ->active(CarbonImmutable::now())
            ->update([
                'completed_steps' => json_encode(array_map(static fn (ChallengeStep $completedStep): string => $completedStep->value, $completed), JSON_THROW_ON_ERROR),
                'required_steps' => json_encode(array_map(static fn (ChallengeRequirement $requirement): array => $requirement->toStorage(), $remaining), JSON_THROW_ON_ERROR),
                'context' => json_encode($stored, JSON_THROW_ON_ERROR),
                'version' => $challenge->version + 1,
            ]);

        if ($advanced === 0) {
            throw new ChallengeInvalid;
        }

        $account = $challenge->account;

        if ($account instanceof Account) {
            event(new ChallengeStepCompleted($challenge->guard, $account, $step->step, $method));
        }

        $fresh = Models::challenges()->whereKey($challenge->getKey())->first() ?? throw new ChallengeInvalid;

        if ($remaining === []) {
            return LoginResult::authenticated($this->finalize->execute($fresh, $context));
        }

        return LoginResult::challenged(new PendingChallenge(
            token: $token,
            expiresAt: $fresh->expires_at,
            method: $fresh->method,
            completed: $fresh->completed(),
            remaining: $fresh->remaining(),
            attemptsLeft: $fresh->attemptsLeft(),
            challengeId: (int) $fresh->getKey(),
        ));
    }
}
