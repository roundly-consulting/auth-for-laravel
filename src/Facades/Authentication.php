<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Auth\AuthenticationManager;

/**
 * No `Auth` alias on purpose — it would collide with Laravel's own facade.
 *
 * @method static \RoundlyConsulting\Auth\Guards\GuardContext guard(?string $name = null)
 * @method static list<string> guards()
 * @method static \RoundlyConsulting\Auth\Http\RouteRegistrar routes(string $guard)
 * @method static \RoundlyConsulting\Auth\Guards\GuardContext|null currentGuard()
 *
 * @see AuthenticationManager
 */
final class Authentication extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return AuthenticationManager::class;
    }
}
