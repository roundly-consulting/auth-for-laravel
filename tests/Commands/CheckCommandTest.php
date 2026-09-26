<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\PlainAccount;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;

it('passes on a healthy configuration', function (): void {
    $this->artisan('authentication:check')
        ->expectsOutputToContain('Configuration and wiring')
        ->assertSuccessful();
});

it('checks one guard, and refuses an unknown one', function (): void {
    $this->artisan('authentication:check', ['guard' => 'clients'])->assertSuccessful();
    $this->artisan('authentication:check', ['guard' => 'staff'])->assertFailed();
});

it('fails on each broken piece of wiring', function (Closure $break, string $message): void {
    $break();

    $this->artisan('authentication:check')->expectsOutputToContain($message)->assertFailed();
})->with([
    'config rule' => [fn () => test()->configureGuard('users', ['registration.mode' => 'invite_only', 'invitations.enabled' => false]), 'invitations.enabled'],
    'user provider' => [fn () => config()->set('auth.providers.users', ['driver' => 'eloquent', 'model' => 'x']), 'must use a provider'],
    'missing columns' => [fn () => Schema::table('users', fn ($table) => $table->dropColumn('timezone')), 'missing columns: timezone'],
    'url template' => [fn () => test()->configureGuard('users', ['notifications.urls.magic_link' => '{frontend}/x']), 'must contain {token}'],
    'keys' => [fn () => config()->set('jwt.private_key_path', '/nope.pem'), 'jwt.private_key_path'],
    'mail' => [fn () => config()->set('mail.default', null), 'mail.default'],
    'revoker' => [fn () => app()->instance(AccessTokenRevoker::class, new NullAccessTokenRevoker), 'AccessTokenRevoker'],
    'routes' => [function (): void {
        config()->set('authentication.guards.staff', ['model' => PlainAccount::class, 'two_factor' => ['mode' => 'off'], 'passkeys' => ['mode' => 'off', 'second_factor' => 'off'], 'routes' => ['enabled' => true]]);
        config()->set('auth.guards.staff', ['driver' => 'jwt', 'provider' => 'staff', 'audience' => 'app-staff']);
        config()->set('auth.providers.staff', ['driver' => 'authentication', 'guard' => 'staff']);
        app(GuardRegistry::class)->flush();
    }, 'routes are not registered'],
]);

it('reports warnings without failing', function (): void {
    $this->configureGuard('users', ['notifications.delivery' => 'queue']);

    $this->artisan('authentication:check')->expectsOutputToContain('queue.default is sync')->assertSuccessful();
});
