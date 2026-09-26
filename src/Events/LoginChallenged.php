<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;

/**
 * A first factor verified and a challenge was started.
 */
final readonly class LoginChallenged
{
    /**
     * @param  list<ChallengeRequirement>  $remaining
     */
    public function __construct(
        public string $guard,
        public Account $account,
        public int $challengeId,
        public array $remaining,
    ) {}
}
