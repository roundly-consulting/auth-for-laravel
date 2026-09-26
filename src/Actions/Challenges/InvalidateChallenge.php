<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Ends a challenge whose remaining steps no longer fit the account (the factor a step
 * would enrol was set up meanwhile): a conditional write, then the uniform
 * {@see ChallengeInvalid}. A fresh login resolves the steps the account needs now.
 */
final class InvalidateChallenge
{
    public function execute(LoginChallenge $challenge, string $reason = 'factor_changed'): never
    {
        Models::challenges()
            ->whereKey($challenge->getKey())
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->update(['invalidated_at' => CarbonImmutable::now(), 'invalidated_reason' => $reason]);

        throw new ChallengeInvalid;
    }
}
