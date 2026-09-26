<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\TokenVersionResolver;

/**
 * Publishes the config and migrations (plus the lower packages' migrations the default
 * features need) and prints the host wiring. It never edits host config files.
 */
final class InstallCommand extends Command
{
    protected $signature = 'authentication:install {--guard=users : The guard to print the wiring for}';

    protected $description = 'Publish the authentication config and migrations and print the auth/jwt wiring';

    public function handle(GuardRegistry $guards): int
    {
        foreach (['authentication-config', 'authentication-migrations', 'refresh-tokens-migrations', 'two-factor-migrations', 'passkeys-migrations'] as $tag) {
            $this->callSilently('vendor:publish', ['--tag' => $tag]);
            $this->components->task("Published [{$tag}]");
        }

        $guard = $this->text('guard');

        $this->newLine();
        $this->components->info('Add to config/auth.php:');
        $this->line(self::authSnippet($guard, $guards->has($guard) ? $guards->all()[$guard]->laravelGuard() : $guard));
        $this->components->info('And to config/jwt.php (guard section):');
        $this->line("    'token_version' => \\".TokenVersionResolver::class.'::class,');
        $this->newLine();
        $this->line('Then run <comment>php artisan migrate</comment> and <comment>php artisan authentication:check</comment>.');

        return self::SUCCESS;
    }

    public static function authSnippet(string $guard, string $laravelGuard): string
    {
        $audience = strtoupper(preg_replace('/\W/', '_', $guard) ?? $guard);

        return <<<PHP
            'guards' => [
                '{$laravelGuard}' => ['driver' => 'jwt', 'provider' => '{$laravelGuard}', 'audience' => env('JWT_{$audience}_AUDIENCE', '{$guard}')],
            ],
            'providers' => [
                '{$laravelGuard}' => ['driver' => 'authentication', 'guard' => '{$guard}'],
            ],
        PHP;
    }

    /**
     * A string argument or option ('' when absent).
     */
    private function text(string $key): string
    {
        $value = $this->hasArgument($key) ? $this->argument($key) : $this->option($key);

        return is_string($value) ? $value : '';
    }
}
