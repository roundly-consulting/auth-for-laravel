<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

/**
 * The one reader of `authentication.tables.*`. Migrations and models resolve their
 * table names here, so a renamed table is the one the model queries.
 */
final class Tables
{
    public static function challenges(): string
    {
        return self::name(config('authentication.tables.challenges'), 'auth_login_challenges');
    }

    public static function oneTimeTokens(): string
    {
        return self::name(config('authentication.tables.one_time_tokens'), 'auth_one_time_tokens');
    }

    public static function invitations(): string
    {
        return self::name(config('authentication.tables.invitations'), 'auth_invitations');
    }

    public static function loginActivities(): string
    {
        return self::name(config('authentication.tables.login_activities'), 'auth_login_activities');
    }

    private static function name(mixed $configured, string $default): string
    {
        return is_string($configured) && $configured !== '' ? $configured : $default;
    }
}
