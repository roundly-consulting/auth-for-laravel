<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * A frontend URL template the package renders into emails.
 */
enum UrlKind: string
{
    use Helpers;

    case MagicLink = 'magic_link';
    case VerifyEmail = 'verify_email';
    case ResetPassword = 'reset_password';
    case ConfirmEmailChange = 'confirm_email_change';
    case Invitation = 'invitation';
}
