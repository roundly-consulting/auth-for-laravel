<?php

declare(strict_types=1);

it('publishes and prints the wiring', function (): void {
    $this->artisan('authentication:install', ['--guard' => 'users'])
        ->expectsOutputToContain('authentication-config')
        ->expectsOutputToContain("'driver' => 'authentication', 'guard' => 'users'")
        ->expectsOutputToContain('TokenVersionResolver')
        ->assertSuccessful();

    expect(config_path('authentication.php'))->toBeFile();
});
