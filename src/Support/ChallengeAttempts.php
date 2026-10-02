<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Models\LoginChallenge;

/**
 * The attempt budget of a challenge step that checks a guessable code. An attempt is
 * taken BEFORE the code is checked (`attempts = attempts + 1 WHERE attempts < max AND
 * still active`), so of any number of overlapping submissions at most the remaining
 * budget is ever checked. A wrong code keeps its attempt; a code that verified, or was
 * never checked, gives it back.
 *
 * @internal a challenge-engine helper.
 */
final readonly class ChallengeAttempts
{
    /**
     * @throws ChallengeInvalid when in-flight or failed guesses already hold every attempt
     */
    public function take(LoginChallenge $challenge): void
    {
        $taken = Models::challenges()
            ->whereKey($challenge->getKey())
            ->whereColumn('attempts', '<', 'max_attempts')
            ->active(CarbonImmutable::now())
            ->increment('attempts');

        if ($taken === 0) {
            throw new ChallengeInvalid;
        }
    }

    public function giveBack(LoginChallenge $challenge): void
    {
        Models::challenges()
            ->whereKey($challenge->getKey())
            ->where('attempts', '>', 0)
            ->decrement('attempts');
    }
}
