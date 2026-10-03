<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use RoundlyConsulting\Auth\AuthenticationServiceProvider;
use RoundlyConsulting\Auth\Support\AuthenticationColumns;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;

it('never auto-loads its migrations', function (): void {
    expect(AuthenticationServiceProvider::class)->toNotAutoLoadMigrations();
});

it('publishes the four tables and the users stub, timestamped', function (): void {
    expect(AuthenticationServiceProvider::class)->toPublishMigrationsTimestamped('authentication-migrations', 5);
});

it('registers both schema macros at boot', function (): void {
    expect(Blueprint::hasMacro('morphKey'))->toBeTrue()
        ->and(Blueprint::hasMacro('authenticationColumns'))->toBeTrue();
});

it('targets the default guard model table, else users', function (): void {
    expect(AuthenticationColumns::defaultTable())->toBe('users');

    config()->set('authentication.default', 'clients');
    expect(AuthenticationColumns::defaultTable())->toBe((new Client)->getTable());

    config()->set('authentication.guards.clients.model', 'App\\Models\\Missing');
    expect(AuthenticationColumns::defaultTable())->toBe('users');
});

it('reads a blank default guard as the users guard when picking the table (strict config)', function (): void {
    config()->set('authentication.guards.users.model', Client::class);
    config()->set('authentication.default', '');

    expect(AuthenticationColumns::defaultTable())->toBe((new Client)->getTable());
});
