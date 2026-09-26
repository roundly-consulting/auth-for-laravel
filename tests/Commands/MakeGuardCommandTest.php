<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\ConfigValidation;
use Symfony\Component\Process\Process;

beforeEach(function (): void {
    $this->scaffold = sys_get_temp_dir().'/authentication-guard-'.getmypid().'-'.random_int(1000, 9999);
    File::ensureDirectoryExists($this->scaffold.'/app');
    File::ensureDirectoryExists($this->scaffold.'/database');
    $this->app->useAppPath($this->scaffold.'/app');
    $this->app->useDatabasePath($this->scaffold.'/database');
});

afterEach(function (): void {
    File::deleteDirectory($this->scaffold);
});

function lint(string $file): void
{
    $process = new Process([PHP_BINARY, '-l', $file]);
    $process->run();

    expect($process->isSuccessful())->toBeTrue($process->getErrorOutput().$process->getOutput());
}

it('scaffolds a model, a migration and a factory that lint and migrate', function (): void {
    $this->artisan('authentication:guard', ['name' => 'staff'])
        ->expectsOutputToContain("'staff' => ['model' =>")
        ->expectsOutputToContain("'driver' => 'authentication', 'guard' => 'staff'")
        ->assertSuccessful();

    $model = $this->scaffold.'/app/Models/Staff.php';
    $migration = File::glob($this->scaffold.'/database/migrations/*_create_staff_table.php')[0] ?? '';
    $factory = $this->scaffold.'/database/factories/StaffFactory.php';

    foreach ([$model, $migration, $factory] as $file) {
        expect($file)->toBeFile();
        lint($file);
    }

    expect(File::get($model))->toContain('implements Account, HasPasskeys, TwoFactorAuthenticatable')
        ->toContain('use HasTwoFactorAuthentication;')
        ->and(File::get($migration))->toContain('$table->authenticationColumns();')->toContain('$table->twoFactorColumns();')->toContain('$table->passkeyUserHandle();');

    (require $migration)->up();

    expect(Schema::hasColumns('staff', ['email', 'token_version', 'two_factor_secret', 'passkey_user_handle']))->toBeTrue();
});

it('leaves out two-factor and passkeys on request, and uses the key type', function (): void {
    config()->set('authentication.key_type', 'uuid');

    $this->artisan('authentication:guard', ['name' => 'clients', '--model' => 'Customer', '--table' => 'customers', '--no-two-factor' => true, '--no-passkeys' => true])->assertSuccessful();

    $model = File::get($this->scaffold.'/app/Models/Customer.php');
    $migration = File::get(File::glob($this->scaffold.'/database/migrations/*_create_customers_table.php')[0]);

    expect($model)->not->toContain('TwoFactor')->not->toContain('Passkey')->toContain("protected \$table = 'customers';")
        ->and($migration)->toContain("\$table->uuid('id')->primary();")->not->toContain('twoFactorColumns');
});

it('refuses to overwrite without --force and rejects bad names', function (): void {
    $this->artisan('authentication:guard', ['name' => 'staff'])->assertSuccessful();
    $this->artisan('authentication:guard', ['name' => 'staff'])->assertFailed();
    $this->artisan('authentication:guard', ['name' => 'staff', '--force' => true])->assertSuccessful();
    $this->artisan('authentication:guard', ['name' => 'staff', '--model' => 'bad name'])->assertFailed();
});

it('scaffolds a model that generates the uuid or ulid key its migration expects', function (string $keyType, string $class, string $trait): void {
    foreach (['authentication.key_type', 'passkeys.key_type', 'refresh-tokens.key_type'] as $key) {
        config()->set($key, $keyType);
    }

    $name = strtolower($class).'s';
    $this->artisan('authentication:guard', ['name' => $name, '--no-two-factor' => true, '--no-passkeys' => true])->assertSuccessful();

    $model = $this->scaffold."/app/Models/{$class}.php";
    expect(File::get($model))->toContain("use {$trait};");

    require $model;
    (require File::glob($this->scaffold."/database/migrations/*_create_{$name}_table.php")[0])->up();

    $fqcn = 'App\\Models\\'.$class;
    $account = (new $fqcn)->forceFill(['email' => "{$name}@example.com", 'password' => 'x']);
    $account->save();

    expect($account->getKey())->toBeString()->not->toBeEmpty();
})->with([
    'uuid' => ['uuid', 'Partner', 'HasUuids'],
    'ulid' => ['ulid', 'Supplier', 'HasUlids'],
]);

it('prints a guard block that validates when two-factor and passkeys are left out', function (): void {
    $this->artisan('authentication:guard', ['name' => 'vendors', '--no-two-factor' => true, '--no-passkeys' => true])
        ->expectsOutputToContain("'vendors' => ['model' => \\App\\Models\\Vendor::class, 'two_factor' => ['mode' => 'off'], 'passkeys' => ['mode' => 'off', 'second_factor' => 'off']],")
        ->assertSuccessful();

    require $this->scaffold.'/app/Models/Vendor.php';

    // Exactly the printed block, merged over the shipped defaults.
    config()->set('authentication.guards.vendors', ['model' => 'App\\Models\\Vendor', 'two_factor' => ['mode' => 'off'], 'passkeys' => ['mode' => 'off', 'second_factor' => 'off']]);
    config()->set('auth.guards.vendors', ['driver' => 'jwt', 'provider' => 'vendors', 'audience' => 'app-vendors']);
    config()->set('auth.providers.vendors', ['driver' => 'authentication', 'guard' => 'vendors']);
    app(GuardRegistry::class)->flush();

    expect(ConfigValidation::problems(app(GuardRegistry::class)->all()['vendors'], app(GuardRegistry::class)))->toBe([]);
});
