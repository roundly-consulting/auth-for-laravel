<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\OneTimeTokens;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Kills an account's still-usable one-time secrets of the given purposes (all purposes
 * when none are given).
 */
final class InvalidateOneTimeTokens
{
    public function execute(string $guard, Account $account, OneTimeTokenPurpose ...$purposes): int
    {
        $model = AccountModels::of($account);
        $now = CarbonImmutable::now();

        return Models::oneTimeTokens()
            ->where('guard', $guard)
            ->where('account_type', $model->getMorphClass())
            ->where('account_id', $model->getKey())
            ->when($purposes !== [], static fn ($query) => $query->whereIn('purpose', array_map(static fn (OneTimeTokenPurpose $purpose): string => $purpose->value, $purposes)))
            ->usable($now)
            ->update(['invalidated_at' => $now]);
    }
}
