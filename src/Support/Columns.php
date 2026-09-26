<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

/**
 * The one reader of `authentication.columns.*` — the column names every guard
 * (account) table carries.
 */
final class Columns
{
    public static function tokenVersion(): string
    {
        return self::name(config('authentication.columns.token_version'), 'token_version');
    }

    public static function locale(): string
    {
        return self::name(config('authentication.columns.locale'), 'locale');
    }

    public static function timezone(): string
    {
        return self::name(config('authentication.columns.timezone'), 'timezone');
    }

    public static function password(): string
    {
        return self::name(config('authentication.columns.password'), 'password');
    }

    public static function passwordChangedAt(): string
    {
        return self::name(config('authentication.columns.password_changed_at'), 'password_changed_at');
    }

    public static function emailVerifiedAt(): string
    {
        return self::name(config('authentication.columns.email_verified_at'), 'email_verified_at');
    }

    public static function lastLoginAt(): string
    {
        return self::name(config('authentication.columns.last_login_at'), 'last_login_at');
    }

    public static function disabledAt(): string
    {
        return self::name(config('authentication.columns.disabled_at'), 'disabled_at');
    }

    public static function disabledReason(): string
    {
        return self::name(config('authentication.columns.disabled_reason'), 'disabled_reason');
    }

    public static function lockedUntil(): string
    {
        return self::name(config('authentication.columns.locked_until'), 'locked_until');
    }

    public static function failedLoginCount(): string
    {
        return self::name(config('authentication.columns.failed_login_count'), 'failed_login_count');
    }

    private static function name(mixed $configured, string $default): string
    {
        return is_string($configured) && $configured !== '' ? $configured : $default;
    }
}
