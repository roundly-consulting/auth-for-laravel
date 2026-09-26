<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Auth\Contracts\AssessesLoginRisk;
use RoundlyConsulting\Auth\Contracts\ChecksBreachedPasswords;
use RoundlyConsulting\Auth\Contracts\FingerprintsDevices;
use RoundlyConsulting\Auth\Contracts\NegotiatesLocale;
use RoundlyConsulting\Auth\Contracts\RendersQrCode;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\AccountUserProvider;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\Middleware\ApplyAccountLocale;
use RoundlyConsulting\Auth\Http\Middleware\EnsureAccountIsActive;
use RoundlyConsulting\Auth\Http\Middleware\EnsureEmailIsVerified;
use RoundlyConsulting\Auth\Http\Middleware\PreventResponseCaching;
use RoundlyConsulting\Auth\Http\Middleware\RequireRecentAuthentication;
use RoundlyConsulting\Auth\Http\Middleware\SetAuthenticationGuard;
use RoundlyConsulting\Auth\Listeners\ReportRefreshTokenReuse;
use RoundlyConsulting\Auth\Support\AboutSection;
use RoundlyConsulting\Auth\Support\AcceptLanguage;
use RoundlyConsulting\Auth\Support\AuthenticationColumns;
use RoundlyConsulting\Auth\Support\DeviceFingerprinter;
use RoundlyConsulting\Auth\Support\JwtAccessTokenRevoker;
use RoundlyConsulting\Auth\Support\NotPwnedPasswordChecker;
use RoundlyConsulting\Auth\Support\NullRiskAssessor;
use RoundlyConsulting\Auth\Support\QrCodeRenderer;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;

final class AuthenticationServiceProvider extends PackageServiceProvider
{
    use RegistersBlueprintMacros;

    public function configurePackage(Package $package): void
    {
        $package
            ->name('authentication')
            ->hasConfigFile()
            ->hasMigrations()
            ->hasMigration('add_authentication_columns_to_users_table')
            ->hasTranslations()
            ->hasCommands([])
            ->contributesToAbout(static fn (): array => AboutSection::data());
    }

    public function register(): void
    {
        parent::register();

        // Scoped: Octane / queue workers get a fresh, config-accurate registry per
        // request or job.
        $this->app->scoped(GuardRegistry::class);
        $this->app->singleton(SecretHasher::class);
        $this->app->singleton(AuthenticationManager::class, static fn (Application $app): AuthenticationManager => new AuthenticationManager($app));

        $this->app->bindIf(FingerprintsDevices::class, DeviceFingerprinter::class);
        $this->app->bindIf(NegotiatesLocale::class, AcceptLanguage::class);
        $this->app->bindIf(RendersQrCode::class, QrCodeRenderer::class);
        $this->app->bindIf(ChecksBreachedPasswords::class, NotPwnedPasswordChecker::class);
        $this->app->bindIf(AssessesLoginRisk::class, NullRiskAssessor::class);

        // refresh-tokens binds a no-op revoker in its own register(); provider order is
        // not guaranteed, so the real adapter is bound once every provider registered.
        $this->app->booting(function (): void {
            $this->app->singleton(AccessTokenRevoker::class, JwtAccessTokenRevoker::class);
        });
    }

    public function boot(): void
    {
        parent::boot();

        // Boot-time, so a standalone `php artisan migrate` has both macros (the fleet's
        // providers that never registered morphKey fataled exactly there).
        $this->registerBlueprintMacros();

        if (! Blueprint::hasMacro('authenticationColumns')) {
            Blueprint::macro('authenticationColumns', function (): void {
                /** @var Blueprint $this */
                AuthenticationColumns::add($this);
            });
        }

        $this->registerMiddleware();
        $this->registerUserProvider();

        Event::listen(RefreshTokenReuseDetected::class, ReportRefreshTokenReuse::class);

        $this->registerConfiguredRoutes();
    }

    private function registerMiddleware(): void
    {
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('authentication.guard', SetAuthenticationGuard::class);
        $router->aliasMiddleware('authentication.verified', EnsureEmailIsVerified::class);
        $router->aliasMiddleware('authentication.reauthenticated', RequireRecentAuthentication::class);
        $router->aliasMiddleware('authentication.locale', ApplyAccountLocale::class);
        $router->aliasMiddleware('authentication.active', EnsureAccountIsActive::class);
        $router->aliasMiddleware('authentication.no-store', PreventResponseCaching::class);
    }

    private function registerUserProvider(): void
    {
        Auth::provider('authentication', static function (Application $app, array $config): AccountUserProvider {
            $guard = $config['guard'] ?? null;

            if (! is_string($guard) || $guard === '') {
                throw AuthenticationMisconfigured::because('An `authentication` user provider needs a `guard` key naming an authentication.guards entry.');
            }

            return new AccountUserProvider($app->make(Hasher::class), $app->make(GuardRegistry::class)->get($guard));
        });
    }

    private function registerConfiguredRoutes(): void
    {
        if ($this->app instanceof CachesRoutes && $this->app->routesAreCached()) {
            return;
        }

        $this->app->booted(function (): void {
            $registry = $this->app->make(GuardRegistry::class);
            $manager = $this->app->make(AuthenticationManager::class);

            foreach ($registry->all() as $name => $guard) {
                // A guard registered both here and by a manual Authentication::routes()
                // call throws: one of the two registrations would be silently dead.
                if ($guard->routesEnabled()) {
                    $manager->routes($name)->register();
                }
            }
        });
    }
}
