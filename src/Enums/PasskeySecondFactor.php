<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Whether (and when) a passkey assertion is a second factor after a first-factor login.
 */
enum PasskeySecondFactor: string
{
    use Helpers;

    case Off = 'off';
    case Allowed = 'allowed';
    case RequiredWhenEnrolled = 'required_when_enrolled';
    case Required = 'required';
}
