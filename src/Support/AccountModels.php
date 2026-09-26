<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Narrows an {@see Account} to the Eloquent model every guard model is (validated at
 * guard resolution), so the lower packages that need `Model&Authenticatable` get one.
 */
final class AccountModels
{
    public static function of(Account $account): Model&Account
    {
        if (! $account instanceof Model) {
            throw AuthenticationMisconfigured::because($account::class.' must be an Eloquent model to be used as an authentication account.');
        }

        return $account;
    }

    public static function twoFactor(Account $account): Model&Account&TwoFactorAuthenticatable
    {
        $model = self::of($account);

        if (! $model instanceof TwoFactorAuthenticatable) {
            throw AuthenticationMisconfigured::because($account::class.' must implement '.TwoFactorAuthenticatable::class.' to use two-factor authentication.');
        }

        return $model;
    }

    public static function passkeys(Account $account): Model&Account&HasPasskeys
    {
        $model = self::of($account);

        if (! $model instanceof HasPasskeys) {
            throw AuthenticationMisconfigured::because($account::class.' must implement '.HasPasskeys::class.' to use passkeys.');
        }

        return $model;
    }
}
