<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;

/**
 * The one reader of `authentication.tables.*`. Migrations and models resolve their
 * table names here, so a renamed table is the one the model queries.
 */
final class Tables
{
    public static function challenges(): string
    {
        return self::name('authentication.tables.challenges', config('authentication.tables.challenges'), 'auth_login_challenges');
    }

    public static function oneTimeTokens(): string
    {
        return self::name('authentication.tables.one_time_tokens', config('authentication.tables.one_time_tokens'), 'auth_one_time_tokens');
    }

    public static function invitations(): string
    {
        return self::name('authentication.tables.invitations', config('authentication.tables.invitations'), 'auth_invitations');
    }

    public static function loginActivities(): string
    {
        return self::name('authentication.tables.login_activities', config('authentication.tables.login_activities'), 'auth_login_activities');
    }

    /**
     * The configured name, or the default when the key is not set (absent, null or blank —
     * an empty env var); a non-string name throws rather than silently reading as the
     * shipped one.
     *
     * @throws AuthenticationMisconfigured
     */
    private static function name(string $key, mixed $configured, string $default): string
    {
        if ($configured === null || (is_string($configured) && trim($configured) === '')) {
            return $default;
        }

        if (! is_string($configured)) {
            throw AuthenticationMisconfigured::because("{$key} must be a string.");
        }

        return $configured;
    }
}
