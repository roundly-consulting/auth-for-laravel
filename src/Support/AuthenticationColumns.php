<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;

/**
 * The columns every guard (account) table carries, registered as the
 * `$table->authenticationColumns()` Blueprint macro. Names come from
 * `authentication.columns.*`.
 */
final class AuthenticationColumns
{
    public static function add(Blueprint $table): void
    {
        $table->unsignedInteger(Columns::tokenVersion())->default(0);
        $table->string(Columns::locale(), 12)->nullable();
        $table->string(Columns::timezone(), 64)->nullable();
        $table->timestamp(Columns::passwordChangedAt())->nullable();
        $table->timestamp(Columns::lastLoginAt())->nullable();
        $table->timestamp(Columns::disabledAt())->nullable();
        $table->string(Columns::disabledReason(), 255)->nullable();
        $table->timestamp(Columns::lockedUntil())->nullable();
        // Only written when lockout is enabled, always through a bounded increment.
        $table->unsignedInteger(Columns::failedLoginCount())->default(0);
    }

    /**
     * The table the published stub alters: the default guard's model table, or `users`
     * while that model does not exist yet (the stub reads config when it runs).
     */
    public static function defaultTable(): string
    {
        $default = config('authentication.default');
        // Not set (null or blank) is the shipped `users` guard, as GuardRegistry reads it.
        $default = $default === null || (is_string($default) && trim($default) === '') ? 'users' : $default;
        $guards = config('authentication.guards');
        $model = is_string($default) && is_array($guards) && is_array($guards[$default] ?? null)
            ? ($guards[$default]['model'] ?? null)
            : null;

        return is_string($model) && is_subclass_of($model, Model::class) ? (new $model)->getTable() : 'users';
    }
}
