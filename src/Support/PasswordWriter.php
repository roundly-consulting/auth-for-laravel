<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\Contracts\Account;
use SensitiveParameter;

/**
 * Stores a new password hash (and `password_changed_at`) with a targeted update.
 */
final class PasswordWriter
{
    public static function write(Account $account, #[SensitiveParameter] string $password): void
    {
        AccountState::write($account, [
            Columns::password() => Hash::make($password),
            Columns::passwordChangedAt() => CarbonImmutable::now(),
        ]);
    }
}
