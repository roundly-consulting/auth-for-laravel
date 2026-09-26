<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\Middleware\SetAuthenticationGuard;

/**
 * Reads the guard a package route serves (set by {@see SetAuthenticationGuard}) and the
 * account authenticated on it.
 */
final class RequestGuard
{
    public const string ATTRIBUTE = 'authentication_guard';

    public static function name(Request $request): string
    {
        $guard = $request->attributes->get(self::ATTRIBUTE) ?? $request->route()?->defaults[self::ATTRIBUTE] ?? null;

        return is_string($guard) && $guard !== '' ? $guard : app(GuardRegistry::class)->defaultGuard();
    }

    /**
     * The route's guard, or an explicitly named one (middleware parameter on host routes).
     */
    public static function config(Request $request, ?string $guard = null): GuardConfig
    {
        return app(GuardRegistry::class)->get($guard !== null && $guard !== '' ? $guard : self::name($request));
    }

    /**
     * The account authenticated on the guard's jwt guard, or null.
     */
    public static function account(Request $request, ?GuardConfig $guard = null): ?Account
    {
        $account = $request->user(($guard ?? self::config($request))->laravelGuard());

        return $account instanceof Account ? $account : null;
    }

    /**
     * The authenticated account; throws (401) when there is none.
     *
     * @throws AuthenticationException
     */
    public static function requireAccount(Request $request, ?GuardConfig $guard = null): Account
    {
        $guard ??= self::config($request);

        return self::account($request, $guard) ?? throw new AuthenticationException(guards: [$guard->laravelGuard()]);
    }
}
