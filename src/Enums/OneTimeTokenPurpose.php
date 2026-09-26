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
     * The purposes invalidated together whenever an account's tokens are invalidated:
     * everything that signs in, re-proves the account or takes it over. A pending email
     * change is one of them — started from a stolen session, it would otherwise survive
     * the owner's password reset or logout and move the account to the thief's address.
     * (A verification link is bound to the current address and changes nothing else.)
     *
     * @return list<self>
     */
    public static function credentialPurposes(): array
    {
        return [self::MagicLink, self::EmailOtp, self::PasswordReset, self::Reauthentication, self::EmailChange];
    }
}
