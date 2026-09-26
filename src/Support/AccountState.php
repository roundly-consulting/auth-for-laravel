<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * Quiet, targeted writes to an account row: a conditional/keyed `UPDATE` of exactly the
 * named columns (no model events, no `updated_at`, no unrelated dirty attribute
 * flushed), reflected back onto the in-memory instance.
 */
final class AccountState
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public static function write(Account $account, array $attributes): void
    {
        $model = AccountModels::of($account);

        $model->newQuery()->whereKey($model->getKey())->update($attributes);

        self::reflect($model, $attributes);
    }

    /**
     * Atomically `token_version = token_version + 1`, never read-modify-write. Returns
     * the new version.
     */
    public static function bumpTokenVersion(Account $account): int
    {
        $model = AccountModels::of($account);
        $column = Columns::tokenVersion();

        $model->newQuery()->whereKey($model->getKey())->increment($column);

        $fresh = $model->newQuery()->whereKey($model->getKey())->value($column);

        self::reflect($model, [$column => (int) $fresh]);

        return (int) $fresh;
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private static function reflect(Model $model, array $attributes): void
    {
        foreach ($attributes as $column => $value) {
            $model->setAttribute($column, $value);
            $model->syncOriginalAttribute($column);
        }
    }
}
