<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * What an account may re-authenticate with: the guard's `reauthentication.methods`,
 * narrowed to what the account actually has — and, under
 * `require_second_factor_when_enrolled`, to its second factor alone (a stolen session
 * plus a leaked password must not be able to disable the factor protecting it).
 * `email_otp` is only ever offered to accounts with neither a password nor a second
 * factor.
 */
final class ReauthenticationMethods
{
    /**
     * @return list<ReauthenticationMethod>
     */
    public static function available(GuardConfig $guard, Account $account): array
    {
        $hasTotp = self::hasTotp($guard, $account);
        $hasPasskeys = self::hasPasskeys($guard, $account);
        $strong = $hasTotp || $hasPasskeys;
        $restrictToSecondFactor = $strong && $guard->reauthenticationRequiresSecondFactorWhenEnrolled();

        return array_values(array_filter(
            $guard->reauthenticationMethods(),
            static fn (ReauthenticationMethod $method): bool => match ($method) {
                ReauthenticationMethod::Password => ! $restrictToSecondFactor && $account->hasPassword(),
                ReauthenticationMethod::Totp, ReauthenticationMethod::RecoveryCode => $hasTotp,
                ReauthenticationMethod::Passkey => $hasPasskeys,
                ReauthenticationMethod::EmailOtp => ! $strong && ! $account->hasPassword() && $account->accountEmail() !== null,
            },
        ));
    }

    public static function hasTotp(GuardConfig $guard, Account $account): bool
    {
        return $guard->twoFactorMode() !== TwoFactorMode::Off
            && $account instanceof TwoFactorAuthenticatable
            && $account->hasTwoFactorEnabled();
    }

    public static function hasPasskeys(GuardConfig $guard, Account $account): bool
    {
        return $guard->passkeyMode() !== PasskeyMode::Off
            && $account instanceof HasPasskeys
            && $account->passkeys()->exists();
    }
}
