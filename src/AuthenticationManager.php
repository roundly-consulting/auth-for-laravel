<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth;

use Illuminate\Contracts\Container\Container;
use Illuminate\Routing\Router;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardContext;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\RouteRegistrar;

/**
 * The entry point behind the {@see Facades\Authentication} facade: per-guard contexts
 * and the opt-in route registrar.
 */
final class AuthenticationManager
{
    /** @var array<string, true> */
    private array $routedGuards = [];

    public function __construct(private readonly Container $app) {}

    /**
     * The discoverable per-guard surface (null → `authentication.default`).
     */
    public function guard(?string $name = null): GuardContext
    {
        return new GuardContext($this->registry()->get($name), $this->app);
    }

    /**
     * @return list<string>
     */
    public function guards(): array
    {
        return $this->registry()->names();
    }

    /**
     * Register a guard's JSON endpoints (fluent; registers on destruct).
     */
    public function routes(string $guard): RouteRegistrar
    {
        $config = $this->registry()->get($guard);

        if (isset($this->routedGuards[$config->name()])) {
            throw AuthenticationMisconfigured::routesAlreadyRegistered($config->name());
        }

        return new RouteRegistrar($this->app->make(Router::class), $config, $this);
    }

    /**
     * The guard the current request's package route serves, if any.
     */
    public function currentGuard(): ?GuardContext
    {
        if (! $this->app->bound('request')) {
            return null;
        }

        $guard = $this->app->make('request')->attributes->get(RequestGuard::ATTRIBUTE);

        return is_string($guard) ? $this->guard($guard) : null;
    }

    /**
     * @internal called by the registrar; a second registration for a guard is a misconfiguration.
     */
    public function markRoutesRegistered(string $guard): void
    {
        if (isset($this->routedGuards[$guard])) {
            throw AuthenticationMisconfigured::routesAlreadyRegistered($guard);
        }

        $this->routedGuards[$guard] = true;
    }

    public function routesRegistered(string $guard): bool
    {
        return isset($this->routedGuards[$guard]);
    }

    private function registry(): GuardRegistry
    {
        return $this->app->make(GuardRegistry::class);
    }
}
