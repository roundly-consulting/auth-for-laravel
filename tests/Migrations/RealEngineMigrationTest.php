<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use RoundlyConsulting\Testing\Assertions\Migrations\MigrationRunner;

/**
 * The four create migrations plus the users stub, applied after a users table — on a
 * real Postgres. Skips visibly when no Postgres is reachable.
 */
function migrationSetWithStub(): string
{
    $dir = sys_get_temp_dir().'/authentication-migrations-'.getmypid();

    File::deleteDirectory($dir);
    File::ensureDirectoryExists($dir);

    File::copy(__DIR__.'/../Fixtures/database/migrations/0001_01_01_000000_create_fixture_accounts_tables.php', $dir.'/0001_01_01_000000_create_fixture_accounts_tables.php');

    foreach (glob(__DIR__.'/../../database/migrations/*.php') ?: [] as $file) {
        File::copy($file, $dir.'/'.basename($file));
    }

    File::copy(__DIR__.'/../../database/migrations/add_authentication_columns_to_users_table.php.stub', $dir.'/2026_09_26_000005_add_authentication_columns_to_users_table.php');

    return $dir;
}

it('applies the four create migrations on postgres', function (): void {
    expect(__DIR__.'/../../database/migrations')->toApplyOnConnection('pgsql', 4);
})->skip(fn (): bool => ! MigrationRunner::connectionIsAvailable('pgsql'), 'no postgres');

it('rejects the users stub ordered before the users table on postgres', function (): void {
    $dir = migrationSetWithStub();

    // The fixture already carries the columns; drop them from the copy so the stub has work to do.
    $fixture = $dir.'/0001_01_01_000000_create_fixture_accounts_tables.php';
    File::put($fixture, str_replace('$table->authenticationColumns();', '', File::get($fixture)));

    expect($dir)->toApplyOnConnection('pgsql', 6)
        ->toRejectBrokenOrderOnConnection(static function (array $files): array {
            $stub = array_values(array_filter($files, static fn (string $file): bool => str_contains($file, 'add_authentication_columns')));
            $rest = array_values(array_filter($files, static fn (string $file): bool => ! str_contains($file, 'add_authentication_columns')));

            return [...$stub, ...$rest];
        }, 'pgsql');
})->skip(fn (): bool => ! MigrationRunner::connectionIsAvailable('pgsql'), 'no postgres');
