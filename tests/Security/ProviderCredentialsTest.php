<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Auth\Guards\AccountUserProvider;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\Fixtures\Support\PreFixTokenGuard;

/**
 * GHSA-f9x3-7vq9-cph6: Laravel's `token` guard (before 12.68 / 13.29) handed any non-empty
 * input, arrays included, to the provider. On MySQL `email IN (0)` casts every letter-first
 * address to 0 and matches it, so the provider itself must refuse anything but a string.
 */
function accountProvider(): AccountUserProvider
{
    $provider = Auth::createUserProvider('users');

    expect($provider)->toBeInstanceOf(AccountUserProvider::class);

    /** @var AccountUserProvider $provider */
    return $provider;
}

/**
 * Run a lookup and return the queries it sent.
 *
 * @return list<string>
 */
function queriesOf(Closure $call): array
{
    DB::flushQueryLog();
    DB::enableQueryLog();

    try {
        $call();
    } finally {
        DB::disableQueryLog();
    }

    return array_values(array_map(static fn (array $query): string => $query['query'], DB::getQueryLog()));
}

dataset('non-string credentials', [
    'array [0]' => [[0]],
    'nested array [[0]]' => [[[0]]],
    'int 0' => [0],
    'false' => [false],
    'true' => [true],
    'null' => [null],
    'float 0.0' => [0.0],
    "assoc ['a' => 1]" => [['a' => 1]],
    'empty string' => [''],
    'arrayable [0]' => [fn (): mixed => collect([0])],
    'query closure' => [fn (): Closure => static function (Builder $query): void {}],
]);

it('never looks an account up by a non-string credential', function (mixed $value): void {
    User::factory()->create(['email' => 'ada@example.com']);
    $provider = accountProvider();
    $account = 'unset';

    $queries = queriesOf(function () use ($provider, $value, &$account): void {
        $account = $provider->retrieveByCredentials(['email' => $value, 'password' => 'correct-horse-battery']);
    });

    expect($account)->toBeNull()
        ->and($queries)->toBe([]);
})->with('non-string credentials');

it('never looks an account up by a credential without a column name', function (): void {
    User::factory()->create(['email' => 'ada@example.com']);
    $provider = accountProvider();

    expect(queriesOf(fn () => expect($provider->retrieveByCredentials(['ada@example.com']))->toBeNull()))->toBe([]);
});

it('finds an active account by its string credentials and never queries the password', function (): void {
    $ada = User::factory()->create(['email' => 'ada@example.com']);
    $provider = accountProvider();

    expect($provider->retrieveByCredentials(['email' => 'ada@example.com', 'password' => ['not', 'a', 'string']])?->getAuthIdentifier())->toBe($ada->getKey())
        ->and($provider->retrieveByCredentials(['email' => 'grace@example.com']))->toBeNull()
        ->and(queriesOf(fn () => expect($provider->retrieveByCredentials(['password' => 'correct-horse-battery']))->toBeNull()))->toBe([]);
});

it('never returns a disabled account by credentials', function (): void {
    User::factory()->disabled()->create(['email' => 'off@example.com']);
    $provider = accountProvider();

    expect($provider->retrieveByCredentials(['email' => 'off@example.com']))->toBeNull();
});

it('keeps a pre-fix token guard on the provider from authenticating array input', function (mixed $token): void {
    $ada = User::factory()->create(['email' => 'ada@example.com']);

    Auth::extend('pre-fix-token', static fn ($app, string $name, array $config): PreFixTokenGuard => new PreFixTokenGuard(
        Auth::createUserProvider($config['provider']) ?? throw new LogicException('No provider.'),
        $app->make('request'),
        'api_token',
        'email',
    ));
    config()->set('auth.guards.host-token', ['driver' => 'pre-fix-token', 'provider' => 'users']);
    Route::post('/host/whoami', static fn (Request $request): array => ['email' => $request->user('host-token')?->email])
        ->middleware('auth:host-token');

    $this->postJson('/host/whoami', ['api_token' => $token])->assertUnauthorized();

    // The same guard still authenticates a real (string) token, so the 401 is the provider's doing.
    Auth::forgetGuards();
    $this->postJson('/host/whoami', ['api_token' => $ada->email])->assertOk()->assertJson(['email' => 'ada@example.com']);
})->with([
    'array [0]' => [[0]],
    'nested array [[0]]' => [[[0]]],
]);

it('validates only a string password', function (mixed $password): void {
    $ada = User::factory()->create();
    $provider = accountProvider();

    expect($provider->validateCredentials($ada, ['password' => $password]))->toBeFalse();
})->with([
    'array [0]' => [[0]],
    'nested array [[0]]' => [[[0]]],
    "assoc ['a' => 1]" => [['a' => 1]],
    'int 0' => [0],
    'null' => [null],
]);

it('validates a string password and refuses a missing one', function (): void {
    $ada = User::factory()->create();
    $provider = accountProvider();

    expect($provider->validateCredentials($ada, ['password' => 'correct-horse-battery']))->toBeTrue()
        ->and($provider->validateCredentials($ada, ['password' => 'wrong-horse-battery']))->toBeFalse()
        ->and($provider->validateCredentials($ada, ['email' => $ada->email]))->toBeFalse();
});
