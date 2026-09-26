<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * A method that can satisfy a challenge step.
 */
enum FactorMethod: string
{
    use Helpers;

    case Totp = 'totp';
    case RecoveryCode = 'recovery_code';
    case Passkey = 'passkey';
    case TotpEnrolment = 'totp_enrolment';
    case PasskeyEnrolment = 'passkey_enrolment';
}
