<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The kind of authentication attempt a login-activity row records.
 */
enum ActivityType: string
{
    use Helpers;

    case PasswordLogin = 'password_login';
    case MagicLinkRequest = 'magic_link_request';
    case MagicLinkLogin = 'magic_link_login';
    case EmailOtpRequest = 'email_otp_request';
    case EmailOtpLogin = 'email_otp_login';
    case PasskeyLogin = 'passkey_login';
    case ChallengeStep = 'challenge_step';
    case Registration = 'registration';
    case InvitationAccepted = 'invitation_accepted';
    case PasswordResetRequest = 'password_reset_request';
    case PasswordReset = 'password_reset';
    case Reauthentication = 'reauthentication';
    case Refresh = 'refresh';
    case Logout = 'logout';
}
