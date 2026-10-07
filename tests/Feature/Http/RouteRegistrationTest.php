<?php

declare(strict_types=1);

use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Route as RouteFacade;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\RouteRegistrar;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\PlainAccount;

/**
 * @return list<Route>
 */
function packageRoutes(string $guard): array
{
    return array_values(array_filter(
        RouteFacade::getRoutes()->getRoutes(),
        static fn (Route $route): bool => str_starts_with((string) $route->getName(), "authentication.{$guard}."),
    ));
}

it('guards every package route with the guard binding and no-store', function (): void {
    $routes = [...packageRoutes('users'), ...packageRoutes('clients')];

    expect($routes)->not->toBeEmpty();

    foreach ($routes as $route) {
        expect($route->gatherMiddleware())
            ->toContain('authentication.no-store')
            ->toContain('authentication.guard:'.$route->defaults['authentication_guard']);
    }
});

it('puts the authenticated group behind the guard\'s jwt guard', function (): void {
    $me = RouteFacade::getRoutes()->getByName('authentication.users.me');

    expect($me?->gatherMiddleware())->toContain('auth:users')
        ->and(RouteFacade::getRoutes()->getByName('authentication.users.refresh')?->gatherMiddleware())->not->toContain('auth:users');
});

it('refuses to register a guard twice', function (): void {
    Authentication::routes('users');
})->throws(AuthenticationMisconfigured::class, 'already registered');

function staffGuard(): void
{
    config()->set('authentication.guards.staff', ['model' => PlainAccount::class, 'two_factor' => ['mode' => 'off'], 'passkeys' => ['mode' => 'off', 'second_factor' => 'off']]);
    config()->set('auth.guards.staff', ['driver' => 'jwt', 'provider' => 'staff', 'audience' => 'app-staff']);
    app(GuardRegistry::class)->flush();
}

it('filters definitions with only and except', function (): void {
    staffGuard();
    $registrar = new RouteRegistrar(app('router'), app(GuardRegistry::class)->get('staff'), app(AuthenticationManager::class));

    $only = array_unique(array_map(fn ($route) => $route->group, $registrar->only(['sessions'])->definitions()));
    $except = array_map(fn ($route) => $route->group, $registrar->only([])->except(['sessions', 'tokens'])->definitions());

    expect(array_values($only))->toBe(['sessions'])
        ->and($except)->not->toContain('sessions')->not->toContain('tokens');
});

it('registers on destruct with a custom prefix, name and middleware', function (): void {
    staffGuard();

    (function (): void {
        Authentication::routes('staff')->prefix('/admin/auth/')->name('admin.')->middleware('api')->authenticatedMiddleware(['throttle:60,1']);
    })();

    RouteFacade::getRoutes()->refreshNameLookups();
    $refresh = RouteFacade::getRoutes()->getByName('admin.refresh');
    $me = RouteFacade::getRoutes()->getByName('admin.me');

    expect($refresh?->uri())->toBe('admin/auth/refresh')
        ->and($me?->gatherMiddleware())->toContain('throttle:60,1')->toContain('auth:staff');
});

/**
 * Regression (chat review C-18): two routed guards sharing a prefix or a name passed. Laravel
 * keeps only the last route per URL (a users magic-link request was served by clients and sent
 * no mail), and a shared name breaks `route:cache`. A fresh manager stands in for a fresh boot.
 */
it('refuses a second guard on a prefix another guard took', function (Closure $register): void {
    $this->configureGuard('users', ['routes.prefix' => 'auth']);
    $this->configureGuard('clients', ['routes.prefix' => 'auth']);
    $manager = new AuthenticationManager;

    $manager->routes('users')->register();

    expect(fn () => $register($manager))->toThrow(AuthenticationMisconfigured::class, 'Routes for the authentication guard [clients] use the prefix [auth], already taken by guard [users]')
        ->and($manager->routesRegistered('clients'))->toBeFalse();
})->with([
    'routes.enabled' => [fn (AuthenticationManager $manager) => $manager->routes('clients')->register()],
    'destruct' => [function (AuthenticationManager $manager): void {
        $manager->routes('clients');
    }],
]);

it('refuses a second guard on a route name another guard took', function (): void {
    $this->configureGuard('users', ['routes.name' => 'auth.']);
    $this->configureGuard('clients', ['routes.name' => 'auth.']);
    $manager = new AuthenticationManager;

    $manager->routes('users')->register();

    expect(fn () => $manager->routes('clients')->register())
        ->toThrow(AuthenticationMisconfigured::class, 'Routes for the authentication guard [clients] use the name [auth.], already taken by guard [users]');
});

it('refuses a clash made through the fluent prefix and name overrides', function (): void {
    $manager = new AuthenticationManager;

    $manager->routes('users')->register();

    expect(fn () => $manager->routes('clients')->prefix('/users/auth/')->register())
        ->toThrow(AuthenticationMisconfigured::class, 'the prefix [users/auth], already taken by guard [users]')
        ->and(fn () => $manager->routes('clients')->name('authentication.users.')->register())
        ->toThrow(AuthenticationMisconfigured::class, 'the name [authentication.users.], already taken by guard [users]');

    $manager->routes('clients')->prefix('partners/auth')->name('partners.')->register();

    expect($manager->routesRegistered('clients'))->toBeTrue();
});
