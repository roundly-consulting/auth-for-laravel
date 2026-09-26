<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
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
