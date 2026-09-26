<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use SensitiveParameter;

/**
 * A login that needs more steps. The plaintext token is returned to the client once;
 * only its HMAC is stored. `challengeId` is internal (events, activity) — never rendered.
 */
final readonly class PendingChallenge
{
    /**
     * @param  list<ChallengeStep>  $completed
     * @param  list<ChallengeRequirement>  $remaining
     */
    public function __construct(
        #[SensitiveParameter] public string $token,
        public CarbonImmutable $expiresAt,
        public LoginMethod $method,
        public array $completed,
        public array $remaining,
        public int $attemptsLeft,
        public ?int $challengeId = null,
    ) {}
}
