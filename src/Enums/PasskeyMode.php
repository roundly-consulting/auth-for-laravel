<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Per-guard passkey policy.
 */
enum PasskeyMode: string
{
    use Helpers;

    case Off = 'off';
    case Optional = 'optional';
    case Required = 'required';
}
