<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Every notification the package can send; each maps to a configurable class.
 */
enum NotificationType: string
{
    use Helpers;

    case MagicLink = 'magic_link';
    case EmailOtp = 'email_otp';
    case VerifyEmail = 'verify_email';
    case ResetPassword = 'reset_password';
    case PasswordChanged = 'password_changed';
    case EmailChangeConfirmation = 'email_change_confirmation';
    case EmailChangeRequested = 'email_change_requested';
    case EmailChanged = 'email_changed';
    case AccountExists = 'account_exists';
    case Invitation = 'invitation';
    case NewDevice = 'new_device';
    case TwoFactorEnabled = 'two_factor_enabled';
    case TwoFactorDisabled = 'two_factor_disabled';
    case RecoveryCodeUsed = 'recovery_code_used';
    case PasskeyAdded = 'passkey_added';
    case PasskeyRemoved = 'passkey_removed';
    case AccountLocked = 'account_locked';
    case RefreshTokenReuse = 'refresh_token_reuse';
}
