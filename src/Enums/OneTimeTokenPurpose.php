<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What an emailed single-use secret is for. Part of its MAC input, so a secret never crosses purposes.
 */
enum OneTimeTokenPurpose: string
{
    use Helpers;

    case MagicLink = 'magic_link';
    case EmailOtp = 'email_otp';
    case EmailVerification = 'email_verification';
    case PasswordReset = 'password_reset';
    case EmailChange = 'email_change';
    case Reauthentication = 'reauthentication';

    /**
     * The purposes invalidated together whenever an account's tokens are invalidated.
     *
     * @return list<self>
     */
    public static function loginPurposes(): array
    {
        return [self::MagicLink, self::EmailOtp, self::PasswordReset, self::Reauthentication];
    }
}
