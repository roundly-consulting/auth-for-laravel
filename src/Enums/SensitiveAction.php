<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * An action that requires a recent (re-)authentication when listed in `reauthentication.required_for`.
 */
enum SensitiveAction: string
{
    use Helpers;

    case EnableTwoFactor = 'enable_two_factor';
    case DisableTwoFactor = 'disable_two_factor';
    case RegenerateRecoveryCodes = 'regenerate_recovery_codes';
    case RegisterPasskey = 'register_passkey';
    case RemovePasskey = 'remove_passkey';
    case ChangeEmail = 'change_email';
    case SetPassword = 'set_password';
    case LogoutEverywhere = 'logout_everywhere';
}
