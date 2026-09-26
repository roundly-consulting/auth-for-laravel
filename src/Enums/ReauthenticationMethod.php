<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How an authenticated account re-proves itself for a sensitive action.
 */
enum ReauthenticationMethod: string
{
    use Helpers;

    case Password = 'password';
    case Totp = 'totp';
    case RecoveryCode = 'recovery_code';
    case Passkey = 'passkey';
    case EmailOtp = 'email_otp';

    /**
     * Whether this method proves the account's second factor (TOTP, a recovery code or a
     * passkey) — a password or an emailed code does not.
     */
    public function isSecondFactor(): bool
    {
        return match ($this) {
            self::Totp, self::RecoveryCode, self::Passkey => true,
            self::Password, self::EmailOtp => false,
        };
    }
}
