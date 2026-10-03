<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;

/**
 * The one reader of `authentication.columns.*` — the column names every guard
 * (account) table carries.
 */
final class Columns
{
    public static function tokenVersion(): string
    {
        return self::name('authentication.columns.token_version', config('authentication.columns.token_version'), 'token_version');
    }

    public static function locale(): string
    {
        return self::name('authentication.columns.locale', config('authentication.columns.locale'), 'locale');
    }

    public static function timezone(): string
    {
        return self::name('authentication.columns.timezone', config('authentication.columns.timezone'), 'timezone');
    }

    public static function password(): string
    {
        return self::name('authentication.columns.password', config('authentication.columns.password'), 'password');
    }

    public static function passwordChangedAt(): string
    {
        return self::name('authentication.columns.password_changed_at', config('authentication.columns.password_changed_at'), 'password_changed_at');
    }

    public static function emailVerifiedAt(): string
    {
        return self::name('authentication.columns.email_verified_at', config('authentication.columns.email_verified_at'), 'email_verified_at');
    }

    public static function lastLoginAt(): string
    {
        return self::name('authentication.columns.last_login_at', config('authentication.columns.last_login_at'), 'last_login_at');
    }

    public static function disabledAt(): string
    {
        return self::name('authentication.columns.disabled_at', config('authentication.columns.disabled_at'), 'disabled_at');
    }

    public static function disabledReason(): string
    {
        return self::name('authentication.columns.disabled_reason', config('authentication.columns.disabled_reason'), 'disabled_reason');
    }

    public static function lockedUntil(): string
    {
        return self::name('authentication.columns.locked_until', config('authentication.columns.locked_until'), 'locked_until');
    }

    public static function failedLoginCount(): string
    {
        return self::name('authentication.columns.failed_login_count', config('authentication.columns.failed_login_count'), 'failed_login_count');
    }

    /**
     * The configured name, or the default only when the key is absent; a blank or non-string
     * name throws rather than silently reading as the shipped one.
     *
     * @throws AuthenticationMisconfigured
     */
    private static function name(string $key, mixed $configured, string $default): string
    {
        $configured ??= $default;

        if (! is_string($configured) || trim($configured) === '') {
            throw AuthenticationMisconfigured::because("{$key} must be a non-empty string.");
        }

        return $configured;
    }
}
