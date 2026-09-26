<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http;

use Illuminate\Routing\Router;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Http\Controllers\Account\LoginActivityController;
use RoundlyConsulting\Auth\Http\Controllers\Account\MeController;
use RoundlyConsulting\Auth\Http\Controllers\Login\PasswordLoginController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\ListSessionsController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\LogoutController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\LogoutEverywhereController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\LogoutOthersController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\RevokeSessionController;
use RoundlyConsulting\Auth\Http\Controllers\Tokens\RefreshController;

/**
 * Registers a guard's opt-in JSON endpoints (`Authentication::routes('users')`, or
 * `routes.enabled = true`). Fluent; registers itself on destruct when `register()` was
 * not called, like Laravel's pending resource registration.
 *
 * Every route carries `authentication.guard:{guard}` and `authentication.no-store`,
 * and is registered only when its feature is enabled for the guard. Tokens always
 * travel in request bodies, never in the path or query string.
 */
final class RouteRegistrar
{
    private string $prefix;

    private string $name;

    /** @var list<string> */
    private array $middleware;

    /** @var list<string> */
    private array $authenticatedMiddleware;

    /** @var list<string> */
    private array $only = [];

    /** @var list<string> */
    private array $except = [];

    private bool $registered = false;

    public function __construct(
        private readonly Router $router,
        private readonly GuardConfig $guard,
        private readonly AuthenticationManager $manager,
    ) {
        $this->prefix = $guard->routePrefix();
        $this->name = $guard->routeName();
        $this->middleware = $guard->routeMiddleware();
        $this->authenticatedMiddleware = $guard->authenticatedRouteMiddleware();
    }

    public function __destruct()
    {
        if (! $this->registered) {
            $this->register();
        }
    }

    public function prefix(string $prefix): self
    {
        $this->prefix = trim($prefix, '/');

        return $this;
    }

    public function name(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * @param  list<string>|string  $middleware
     */
    public function middleware(array|string $middleware): self
    {
        $this->middleware = is_array($middleware) ? $middleware : [$middleware];

        return $this;
    }

    /**
     * @param  list<string>|string  $middleware
     */
    public function authenticatedMiddleware(array|string $middleware): self
    {
        $this->authenticatedMiddleware = is_array($middleware) ? $middleware : [$middleware];

        return $this;
    }

    /**
     * @param  list<string>  $groups
     */
    public function only(array $groups): self
    {
        $this->only = $groups;

        return $this;
    }

    /**
     * @param  list<string>  $groups
     */
    public function except(array $groups): self
    {
        $this->except = $groups;

        return $this;
    }

    public function register(): void
    {
        if ($this->registered) {
            return;
        }

        $this->registered = true;
        $this->manager->markRoutesRegistered($this->guard->name());

        $guard = $this->guard->name();

        $this->router->group([
            'prefix' => $this->prefix,
            'as' => $this->name,
            'middleware' => [...$this->middleware, 'authentication.guard:'.$guard, 'authentication.no-store'],
        ], function (Router $router) use ($guard): void {
            foreach ($this->definitions() as $definition) {
                $middleware = $definition->authenticated
                    ? ['auth:'.$this->guard->laravelGuard(), ...$this->authenticatedMiddleware, ...$definition->middleware]
                    : $definition->middleware;

                $router->addRoute($definition->method, $definition->uri, $definition->controller)
                    ->name($definition->name)
                    ->middleware($middleware)
                    ->defaults(RequestGuard::ATTRIBUTE, $guard);
            }
        });
    }

    /**
     * The enabled endpoints this registrar will register (after only/except).
     *
     * @return list<RouteDefinition>
     */
    public function definitions(): array
    {
        return array_values(array_filter(
            $this->all(),
            fn (RouteDefinition $route): bool => $route->enabled
                && ($this->only === [] || in_array($route->group, $this->only, true))
                && ! in_array($route->group, $this->except, true),
        ));
    }

    /**
     * @return list<RouteDefinition>
     */
    private function all(): array
    {
        return [
            // Login
            new RouteDefinition('login', 'POST', 'login', 'login', PasswordLoginController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::Password)),

            // Tokens
            new RouteDefinition('tokens', 'POST', 'refresh', 'refresh', RefreshController::class),

            // Account
            new RouteDefinition('account', 'GET', 'me', 'me', MeController::class, authenticated: true),
            new RouteDefinition('account', 'GET', 'activity', 'activity', LoginActivityController::class, authenticated: true, enabled: $this->guard->activityEnabled()),

            // Sessions
            new RouteDefinition('sessions', 'POST', 'logout', 'logout', LogoutController::class, authenticated: true),
            new RouteDefinition('sessions', 'POST', 'logout/others', 'logout.others', LogoutOthersController::class, authenticated: true),
            new RouteDefinition('sessions', 'POST', 'logout/everywhere', 'logout.everywhere', LogoutEverywhereController::class, authenticated: true),
            new RouteDefinition('sessions', 'GET', 'sessions', 'sessions', ListSessionsController::class, authenticated: true),
            new RouteDefinition('sessions', 'DELETE', 'sessions/{session}', 'sessions.destroy', RevokeSessionController::class, authenticated: true),
        ];
    }
}
