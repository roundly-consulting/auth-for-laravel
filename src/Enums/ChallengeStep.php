<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * One step of a pending login challenge. Verification steps always precede enrolment steps.
 */
enum ChallengeStep: string
{
    use Helpers;

    case SecondFactor = 'second_factor';
    case Passkey = 'passkey';
    case EnrolTwoFactor = 'enrol_two_factor';
    case EnrolPasskey = 'enrol_passkey';

    /**
     * Whether the step enrols a new factor (as opposed to verifying an existing one).
     */
    public function isEnrolment(): bool
    {
        return $this === self::EnrolTwoFactor || $this === self::EnrolPasskey;
    }
}
