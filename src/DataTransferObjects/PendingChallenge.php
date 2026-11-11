<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
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

    /**
     * The completed steps as their wire values. The return types spell the enum values out
     * (Larastan checks them against the cases) because OpenAPI generators read literal
     * unions but not `value-of<>`.
     *
     * @return list<'second_factor'|'passkey'|'enrol_two_factor'|'enrol_passkey'>
     */
    public function completedSteps(): array
    {
        return array_map(static fn (ChallengeStep $step): string => $step->value, $this->completed);
    }

    /**
     * The remaining steps as their wire form: each step and the factor methods that satisfy it.
     *
     * @return list<array{step: 'second_factor'|'passkey'|'enrol_two_factor'|'enrol_passkey', methods: list<'totp'|'recovery_code'|'passkey'|'totp_enrolment'|'passkey_enrolment'>}>
     */
    public function remainingSteps(): array
    {
        return array_map(static fn (ChallengeRequirement $requirement): array => [
            'step' => $requirement->step->value,
            'methods' => array_map(static fn (FactorMethod $method): string => $method->value, $requirement->methods),
        ], $this->remaining);
    }
}
