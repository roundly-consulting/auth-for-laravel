<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\AuthenticationManager;
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

it('lists a junk class leaf next to the other problems instead of crashing', function (): void {
    $this->configureGuard('users', ['registration.rules' => 123, 'registration.mode' => 'invite_only', 'invitations.enabled' => false]);

    $this->artisan('authentication:check', ['guard' => 'users'])
        ->expectsOutputToContain('registration.mode is invite_only')
        ->expectsOutputToContain('registration.rules must be a string')
        ->assertExitCode(1);
});

it('passes after the documented install on a stock users table', function (): void {
    // Laravel's own users table, then the two published column stubs `migrate` runs.
    Schema::drop('users');
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password');
        $table->rememberToken();
        $table->timestamps();
    });

    foreach ([__DIR__.'/../../vendor/roundly-consulting/two-factor-for-laravel/database/migrations/add_two_factor_columns_to_users_table.php.stub', __DIR__.'/../../database/migrations/add_authentication_columns_to_users_table.php.stub'] as $stub) {
        (require $stub)->up();
    }

    expect(Schema::hasColumn('users', 'passkey_user_handle'))->toBeTrue();
    $this->artisan('authentication:check', ['guard' => 'users'])->doesntExpectOutputToContain('missing columns')->assertSuccessful();
});

it('leaves an existing passkey handle column alone', function (): void {
    Schema::drop('users');
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('email')->unique();
        $table->passkeyUserHandle();
    });

    (require __DIR__.'/../../database/migrations/add_authentication_columns_to_users_table.php.stub')->up();

    expect(Schema::hasColumns('users', ['passkey_user_handle', 'token_version']))->toBeTrue();
});

it('reports warnings without failing', function (): void {
    $this->configureGuard('users', ['notifications.delivery' => 'queue']);

    $this->artisan('authentication:check')->expectsOutputToContain('queue.default is sync')->assertSuccessful();
});

it('finds the routes of a guard when they come from the route cache', function (): void {
    // After `route:cache` the provider skips registration: the routes are in the router
    // (loaded from the cache file), but no registrar ever ran in this process.
    expect(Route::has('authentication.users.login'))->toBeTrue();
    $this->app->forgetInstance(AuthenticationManager::class);

    $this->artisan('authentication:check', ['guard' => 'users'])->assertSuccessful();
});

it('judges every run on its own when called again in the same process', function (): void {
    config()->set('mail.default', null);
    $this->artisan('authentication:check')->assertFailed();

    config()->set('mail.default', 'array');
    $this->artisan('authentication:check')->assertSuccessful();
});

it('checks the lower packages\' configured column names', function (): void {
    Schema::table('users', function ($table): void {
        $table->renameColumn('passkey_user_handle', 'webauthn_handle');
        $table->renameColumn('two_factor_secret', 'totp_secret');
    });
    config()->set('passkeys.user.handle_column', 'webauthn_handle');
    config()->set('two-factor.columns.secret', 'totp_secret');

    $this->artisan('authentication:check', ['guard' => 'users'])->assertSuccessful();
});

it('requires the replay-guard column only when two-factor stores the timestep there', function (): void {
    Schema::table('users', fn ($table) => $table->dropColumn('two_factor_last_used_timestep'));

    $this->artisan('authentication:check', ['guard' => 'users'])
        ->expectsOutputToContain('missing columns: two_factor_last_used_timestep')
        ->assertFailed();

    config()->set('two-factor.replay_guard', 'cache');

    $this->artisan('authentication:check', ['guard' => 'users'])->assertSuccessful();
});
