<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Tests\PublishSandboxTestCase;

/**
 * Publishing runs against a throwaway config/ and database/ ({@see PublishSandboxTestCase}),
 * never the testbench skeleton the parallel suite loads its configuration from.
 */
it('publishes into the sandbox, never the shared skeleton', function (): void {
    expect(config_path('authentication.php'))->toContain('authentication-publish-')
        ->and(database_path('migrations'))->toContain('authentication-publish-');
});

it('publishes and prints the wiring', function (): void {
    $this->artisan('authentication:install', ['--guard' => 'users'])
        ->expectsOutputToContain('authentication-config')
        ->expectsOutputToContain("'driver' => 'authentication', 'guard' => 'users'")
        ->expectsOutputToContain('TokenVersionResolver')
        ->assertSuccessful();

    expect(config_path('authentication.php'))->toBeFile();
});
