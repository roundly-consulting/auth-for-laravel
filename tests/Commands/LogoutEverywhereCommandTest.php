<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('logs an account out everywhere by key', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->artisan('authentication:logout-everywhere', ['guard' => 'users', 'id' => (string) $user->getKey()])
        ->expectsOutputToContain('1 session(s) revoked')
        ->assertSuccessful();

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
});

it('fails for an unknown or malformed key', function (): void {
    $this->artisan('authentication:logout-everywhere', ['guard' => 'users', 'id' => '999'])->assertFailed();
    $this->artisan('authentication:logout-everywhere', ['guard' => 'users', 'id' => 'abc'])->assertFailed();
});
