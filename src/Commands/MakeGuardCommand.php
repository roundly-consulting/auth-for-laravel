<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;
use RuntimeException;

/**
 * Scaffolds a new guard: the account model (generating the uuid/ulid key the configured
 * `authentication.key_type` asks for), its create-table migration (with the
 * authentication, two-factor and passkey-handle columns) and a factory — then prints
 * the `authentication.guards` block (switching two-factor / passkeys off when they were
 * left out, since the shipped defaults turn both on) and the `config/auth.php` wiring.
 * Never edits config files.
 */
final class MakeGuardCommand extends Command
{
    protected $signature = 'authentication:guard
        {name : The guard name, e.g. clients}
        {--model= : The model class base name (default: singular studly name)}
        {--table= : The table name (default: the guard name)}
        {--no-two-factor : Leave out two-factor support}
        {--no-passkeys : Leave out passkey support}
        {--force : Overwrite existing files}';

    protected $description = 'Scaffold a new authentication guard (model, migration, factory)';

    public function handle(Filesystem $files): int
    {
        $name = Str::snake($this->text('name'));
        $class = Str::studly($this->text('model') ?: Str::singular($name));
        $table = Str::snake($this->text('table') ?: $name);
        $twoFactor = ! $this->option('no-two-factor');
        $passkeys = ! $this->option('no-passkeys');

        if (preg_match('/^[a-z][a-z0-9_]*$/', $name) !== 1 || preg_match('/^[A-Z][A-Za-z0-9]*$/', $class) !== 1) {
            $this->components->error('The guard and model names must be plain identifiers.');

            return self::FAILURE;
        }

        $namespace = $this->appNamespace().'\\Models';
        $targets = [
            $this->laravel->path("Models/{$class}.php") => $this->model($files, $namespace, $class, $table, $twoFactor, $passkeys),
            $this->laravel->databasePath('migrations/'.date('Y_m_d_His')."_create_{$table}_table.php") => $this->migration($files, $table, $twoFactor, $passkeys),
            $this->laravel->databasePath("factories/{$class}Factory.php") => $this->factory($files, $namespace, $class),
        ];

        foreach ($targets as $path => $contents) {
            if ($files->exists($path) && ! $this->option('force')) {
                $this->components->error("{$path} already exists (use --force).");

                return self::FAILURE;
            }
        }

        foreach ($targets as $path => $contents) {
            $files->ensureDirectoryExists(dirname($path));
            $files->put($path, $contents);
            $this->components->task("Created {$path}");
        }

        $this->newLine();
        $this->components->info('Add to config/authentication.php (guards):');
        $this->line("    '{$name}' => ".$this->guardBlock($namespace, $class, $twoFactor, $passkeys).',');
        $this->components->info('Add to config/auth.php:');
        $this->line(InstallCommand::authSnippet($name, $name));

        return self::SUCCESS;
    }

    /**
     * The guard's `authentication.guards` entry, exactly as printed.
     */
    private function guardBlock(string $namespace, string $class, bool $twoFactor, bool $passkeys): string
    {
        $block = ["'model' => \\{$namespace}\\{$class}::class"];

        if (! $twoFactor) {
            $block[] = "'two_factor' => ['mode' => 'off']";
        }

        if (! $passkeys) {
            $block[] = "'passkeys' => ['mode' => 'off', 'second_factor' => 'off']";
        }

        return '['.implode(', ', $block).']';
    }

    /**
     * The application namespace (`App` when it cannot be detected from composer.json).
     */
    private function appNamespace(): string
    {
        try {
            return rtrim($this->laravel->getNamespace(), '\\');
        } catch (RuntimeException) {
            return 'App';
        }
    }

    private function model(Filesystem $files, string $namespace, string $class, string $table, bool $twoFactor, bool $passkeys): string
    {
        $imports = [
            'Illuminate\Auth\Authenticatable as AuthenticatableConcern',
            'Illuminate\Database\Eloquent\Factories\HasFactory',
            'Illuminate\Database\Eloquent\Model',
            'Illuminate\Database\Eloquent\SoftDeletes',
            'Illuminate\Notifications\Notifiable',
            'RoundlyConsulting\Auth\Concerns\HasAuthentication',
            'RoundlyConsulting\Auth\Contracts\Account',
            'RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens',
        ];
        $interfaces = ['Account'];
        $traits = ['AuthenticatableConcern', 'HasAuthentication', 'HasFactory', 'HasRefreshTokens', 'Notifiable', 'SoftDeletes'];
        $casts = '...$this->authenticationCasts(), ';

        // The migration creates a uuid/ulid primary key; the model must generate it.
        $keyTrait = match (KeyType::fromConfig('authentication.key_type')) {
            KeyType::Uuid => 'HasUuids',
            KeyType::Ulid => 'HasUlids',
            KeyType::BigInt => null,
        };

        if ($keyTrait !== null) {
            $imports[] = 'Illuminate\Database\Eloquent\Concerns\\'.$keyTrait;
            $traits[] = $keyTrait;
        }

        if ($twoFactor) {
            $imports[] = 'RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication';
            $imports[] = 'RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable';
            $interfaces[] = 'TwoFactorAuthenticatable';
            $traits[] = 'HasTwoFactorAuthentication';
            $casts .= '...$this->twoFactorCasts(), ';
        }

        if ($passkeys) {
            $imports[] = 'RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys';
            $imports[] = 'RoundlyConsulting\Passkeys\Contracts\HasPasskeys';
            $interfaces[] = 'HasPasskeys';
            $traits[] = 'InteractsWithPasskeys';
        }

        sort($imports);
        sort($interfaces);
        sort($traits);

        return strtr($files->get($this->stub('guard-model.stub')), [
            '{{ namespace }}' => $namespace,
            '{{ imports }}' => implode("\n", array_map(static fn (string $import): string => "use {$import};", $imports)),
            '{{ class }}' => $class,
            '{{ interfaces }}' => implode(', ', $interfaces),
            '{{ traits }}' => implode("\n", array_map(static fn (string $trait): string => "    use {$trait};", $traits)),
            '{{ table }}' => $table,
            '{{ casts }}' => $casts,
        ]);
    }

    private function migration(Filesystem $files, string $table, bool $twoFactor, bool $passkeys): string
    {
        $id = match (KeyType::fromConfig('authentication.key_type')) {
            KeyType::Uuid => '$table->uuid(\'id\')->primary();',
            KeyType::Ulid => '$table->ulid(\'id\')->primary();',
            KeyType::BigInt => '$table->id();',
        };

        $extra = array_filter([
            $twoFactor ? '            $table->twoFactorColumns();' : null,
            $passkeys ? '            $table->passkeyUserHandle();' : null,
        ]);

        return strtr($files->get($this->stub('guard-migration.stub')), [
            '{{ table }}' => $table,
            '{{ id }}' => $id,
            '{{ password_nullable }}' => '->nullable()',
            '{{ extra_columns }}' => implode("\n", $extra),
        ]);
    }

    private function factory(Filesystem $files, string $namespace, string $class): string
    {
        return strtr($files->get($this->stub('guard-factory.stub')), [
            '{{ factory_namespace }}' => 'Database\Factories',
            '{{ namespace }}' => $namespace,
            '{{ class }}' => $class,
        ]);
    }

    private function stub(string $name): string
    {
        return dirname(__DIR__, 2).'/stubs/'.$name;
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
