<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Commands;

use Illuminate\Console\Command;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\NotificationDelivery;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Support\AboutSection;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\ConfigValidation;
use RoundlyConsulting\Auth\Support\JwtAccessTokenRevoker;
use Throwable;

/**
 * The doctor: every configuration rule, reported as a list instead of the first
 * exception, plus the wiring the package cannot validate at resolution time (user
 * provider, columns, keys, revoker, mail, queue, URL templates, routes). Exits 1 when
 * anything is wrong.
 */
final class CheckCommand extends Command
{
    protected $signature = 'authentication:check {guard? : Check one guard only}';

    protected $description = 'Diagnose the authentication configuration and wiring';

    /** @var list<string> */
    private array $errors = [];

    /** @var list<string> */
    private array $warnings = [];

    private bool $failed = false;

    public function handle(GuardRegistry $registry, Router $router): int
    {
        // The command instance outlives a run (Artisan::call twice in one process).
        $this->failed = false;

        $only = $this->argument('guard');
        $guards = $registry->all();

        if (is_string($only)) {
            if (! isset($guards[$only])) {
                $this->components->error("The authentication guard [{$only}] is not configured.");

                return self::FAILURE;
            }

            $guards = [$only => $guards[$only]];
        }

        foreach ($guards as $name => $guard) {
            $this->errors = [];
            $this->warnings = ConfigValidation::warnings($guard);

            foreach (ConfigValidation::problems($guard, $registry) as $problem) {
                $this->errors[] = $problem;
            }

            if ($this->errors === []) {
                $this->checkWiring($guard, $router);
            }

            $this->report($name);
        }

        $this->checkGlobal();

        return $this->failed ? self::FAILURE : self::SUCCESS;
    }

    private function checkWiring(GuardConfig $guard, Router $router): void
    {
        $laravelGuard = $guard->laravelGuard();
        $provider = config("auth.guards.{$laravelGuard}.provider");
        $providerConfig = is_string($provider) ? config("auth.providers.{$provider}") : null;

        if (! is_array($providerConfig) || ($providerConfig['driver'] ?? null) !== 'authentication' || ($providerConfig['guard'] ?? null) !== $guard->name()) {
            $this->errors[] = "auth.guards.{$laravelGuard} must use a provider with ['driver' => 'authentication', 'guard' => '{$guard->name()}'] (disabled accounts would still authenticate).";
        }

        $this->checkColumns($guard);

        foreach (UrlKind::cases() as $kind) {
            if (! str_contains($guard->urlTemplate($kind), '{token}')) {
                $this->errors[] = "notifications.urls.{$kind->value} must contain {token}.";
            }
        }

        if ($guard->notificationDelivery() === NotificationDelivery::Queue && config('queue.default') === 'sync') {
            $this->warnings[] = 'notifications.delivery is queue but queue.default is sync.';
        }

        if ($guard->routesEnabled() && ! $this->serves($router, $guard)) {
            $this->errors[] = 'routes.enabled is on but the routes are not registered (cached routes from before?).';
        }
    }

    /**
     * Whether the router holds a package route for the guard — read from the router
     * itself, so routes loaded from the route cache count (no registrar ran then).
     */
    private function serves(Router $router, GuardConfig $guard): bool
    {
        foreach ($router->getRoutes()->getRoutes() as $route) {
            if (($route->defaults[RequestGuard::ATTRIBUTE] ?? null) === $guard->name()) {
                return true;
            }
        }

        return false;
    }

    private function checkColumns(GuardConfig $guard): void
    {
        $model = $guard->model();
        $table = (new $model)->getTable();

        $columns = [
            $guard->emailColumn(), Columns::password(), Columns::tokenVersion(), Columns::locale(), Columns::timezone(),
            Columns::passwordChangedAt(), Columns::lastLoginAt(), Columns::disabledAt(), Columns::disabledReason(),
            Columns::lockedUntil(), Columns::failedLoginCount(),
        ];

        if ($guard->verificationMode() !== EmailVerificationMode::Off) {
            $columns[] = Columns::emailVerifiedAt();
        }

        if ($guard->twoFactorMode() !== TwoFactorMode::Off) {
            $columns = [...$columns, 'two_factor_secret', 'two_factor_recovery_codes', 'two_factor_confirmed_at'];
        }

        if ($guard->passkeyMode() !== PasskeyMode::Off) {
            $columns[] = 'passkey_user_handle';
        }

        try {
            $missing = array_values(array_filter($columns, static fn (string $column): bool => ! Schema::hasColumn($table, $column)));
        } catch (Throwable $e) {
            $this->errors[] = "Could not inspect table [{$table}]: {$e->getMessage()}";

            return;
        }

        if ($missing !== []) {
            $this->errors[] = "Table [{$table}] is missing columns: ".implode(', ', $missing).'.';
        }
    }

    private function checkGlobal(): void
    {
        $problems = [];

        if (! AboutSection::revoker() instanceof JwtAccessTokenRevoker) {
            $problems[] = 'refresh-tokens AccessTokenRevoker is not bound to '.JwtAccessTokenRevoker::class.'.';
        }

        foreach (['jwt.private_key_path', 'jwt.public_key_path'] as $key) {
            $path = config($key);

            if (! is_string($path) || $path === '' || ! is_readable(str_starts_with($path, '/') ? $path : base_path($path))) {
                $problems[] = "{$key} does not point at a readable key.";
            }
        }

        if (! is_string(config('mail.default')) || config('mail.default') === '') {
            $problems[] = 'mail.default is not configured; no notification can be delivered.';
        }

        $this->newLine();

        foreach ($problems as $problem) {
            $this->components->twoColumnDetail('<fg=red>✗</>', $problem);
        }

        if ($problems === []) {
            $this->components->twoColumnDetail('Keys, revoker, mail', '<fg=green>OK</>');
        }

        $this->failed = $this->failed || $problems !== [];
    }

    private function report(string $guard): void
    {
        $this->components->info("Guard [{$guard}]");

        foreach ($this->errors as $error) {
            $this->components->twoColumnDetail('<fg=red>✗</>', $error);
        }

        foreach ($this->warnings as $warning) {
            $this->components->twoColumnDetail('<fg=yellow>!</>', $warning);
        }

        if ($this->errors === []) {
            $this->components->twoColumnDetail('Configuration and wiring', '<fg=green>OK</>');
        }

        $this->failed = $this->failed || $this->errors !== [];
    }
}
