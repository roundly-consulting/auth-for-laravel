<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How an account proved its first factor. Also the `method` of a challenge and a session.
 */
enum LoginMethod: string
{
    use Helpers;

    case Password = 'password';
    case MagicLink = 'magic_link';
    case EmailOtp = 'email_otp';
    case Passkey = 'passkey';
    case Invitation = 'invitation';
    case Registration = 'registration';
    case PasswordReset = 'password_reset';
    case Host = 'host';

    /**
     * The activity type a completed or failed login of this method is recorded under.
     */
    public function activityType(): ActivityType
    {
        return match ($this) {
            self::Password, self::Host => ActivityType::PasswordLogin,
            self::MagicLink => ActivityType::MagicLinkLogin,
            self::EmailOtp => ActivityType::EmailOtpLogin,
            self::Passkey => ActivityType::PasskeyLogin,
            self::Invitation => ActivityType::InvitationAccepted,
            self::Registration => ActivityType::Registration,
            self::PasswordReset => ActivityType::PasswordReset,
        };
    }
}
