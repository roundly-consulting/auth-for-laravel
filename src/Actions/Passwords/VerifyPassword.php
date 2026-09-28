<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passwords;

use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\DummyPasswordHash;
use SensitiveParameter;

/**
 * The only place a password is checked. With no account (or no password) the check
 * still runs — against a dummy hash of the same cost — so timing reveals nothing.
 *
 * @internal the timing-safe hash check the flows share.
 */
final class VerifyPassword
{
    public function execute(?Account $account, #[SensitiveParameter] string $password): bool
    {
        $stored = $account === null ? null : AccountModels::of($account)->getAttribute(Columns::password());
        $real = is_string($stored) && $stored !== '';

        $matches = Hash::check($password, $real ? $stored : DummyPasswordHash::get());

        return $real && $matches;
    }
}
