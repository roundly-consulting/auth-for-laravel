<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How strictly a guard enforces a verified email address.
 */
enum EmailVerificationMode: string
{
    use Helpers;

    case Off = 'off';
    case Optional = 'optional';
    case RequiredForActions = 'required_for_actions';
    case RequiredForLogin = 'required_for_login';
}
