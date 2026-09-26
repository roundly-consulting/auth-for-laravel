<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Per-guard TOTP policy.
 */
enum TwoFactorMode: string
{
    use Helpers;

    case Off = 'off';
    case Optional = 'optional';
    case Required = 'required';
}
