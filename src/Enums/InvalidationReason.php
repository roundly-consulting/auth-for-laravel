<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

/**
 * Why an account's tokens are being invalidated.
 */
enum InvalidationReason: string
{
    use Helpers;

    case PasswordChanged = 'password_changed';
    case PasswordReset = 'password_reset';
    case EmailChanged = 'email_changed';
    case TwoFactorChanged = 'two_factor_changed';
    case PasskeyChanged = 'passkey_changed';
    case AccountDisabled = 'account_disabled';
    case Logout = 'logout';
    case Security = 'security';

    /**
     * The refresh-token revocation reason recorded on the sessions this invalidation ends.
     */
    public function revocationReason(): RevocationReason
    {
        return match ($this) {
            self::AccountDisabled => RevocationReason::AccountDisabled,
            self::Logout => RevocationReason::LogoutAll,
            self::Security => RevocationReason::Security,
            default => RevocationReason::CredentialsChanged,
        };
    }

    /**
     * Reasons whose login one-time tokens are invalidated even when the scope is `none`.
     */
    public function alwaysInvalidatesOneTimeTokens(): bool
    {
        return in_array($this, [self::PasswordReset, self::AccountDisabled, self::EmailChanged], true);
    }
}
