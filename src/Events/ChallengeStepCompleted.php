<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;

/**
 * A challenge step was satisfied.
 */
final readonly class ChallengeStepCompleted
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ChallengeStep $step,
        public FactorMethod $method,
    ) {}
}
