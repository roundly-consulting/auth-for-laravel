<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;

/**
 * A challenge step failed (the attempt was counted).
 */
final readonly class ChallengeFailed
{
    public function __construct(
        public string $guard,
        public ?Account $account,
        public ActivityOutcome $outcome,
    ) {}
}
