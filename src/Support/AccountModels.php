<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;

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
}
