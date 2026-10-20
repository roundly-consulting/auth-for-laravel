<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * `findByKey()` is public: a host may hand it a key from a URL. Each engine coerces a
 * malformed one differently — MySQL reads `1abc` as 1, Postgres casts ` 1` and `0x1` to 1 and
 * throws 22P02 on `1abc`, SQLite matches ` 1` and `1.0` — so the shape is checked first.
 */
function accountsOfUsers(): AccountRepository
{
    return Authentication::guard('users')->accounts();
}

it('finds no account by a malformed key', function (string $format): void {
    $ada = User::factory()->create();
    $key = sprintf($format, $ada->getKey());

    expect(accountsOfUsers()->findByKey($key))->toBeNull();
})->with([
    'leading space' => [' %d'],
    'trailing letters' => ['%dabc'],
    'decimal' => ['%d.0'],
    'hex' => ['0x%d'],
    'letters' => ['abc'],
    'leading zero' => ['0%d'],
    'empty' => [''],
    'beyond bigint' => ['99999999999999999999%d'],
]);

it('finds an account by its canonical key, as an int or a string', function (): void {
    $ada = User::factory()->create();

    expect(accountsOfUsers()->findByKey($ada->getKey())?->getAuthIdentifier())->toBe($ada->getKey())
        ->and(accountsOfUsers()->findByKey((string) $ada->getKey())?->getAuthIdentifier())->toBe($ada->getKey());
});

it('checks a key against the configured key type before querying', function (string $keyType, int|string $key, bool $queries): void {
    config()->set('authentication.key_type', $keyType);

    $sent = DB::pretend(fn () => accountsOfUsers()->findByKey($key));

    expect($sent)->toHaveCount($queries ? 1 : 0);
})->with([
    'bigint · int' => ['bigint', 1, true],
    'bigint · zero' => ['bigint', 0, true],
    'bigint · digits' => ['bigint', '42', true],
    'bigint · negative int' => ['bigint', -1, false],
    'bigint · negative digits' => ['bigint', '-1', false],
    'bigint · uuid' => ['bigint', '0199a7a4-6d5e-7c1b-9f3e-2b7c8d9e0f1a', false],
    'uuid · uuid' => ['uuid', '0199a7a4-6d5e-7c1b-9f3e-2b7c8d9e0f1a', true],
    'uuid · upper-case uuid' => ['uuid', '0199A7A4-6D5E-7C1B-9F3E-2B7C8D9E0F1A', true],
    'uuid · int' => ['uuid', 1, false],
    'uuid · digits' => ['uuid', '1', false],
    'uuid · ulid' => ['uuid', '01K7Z3M8Q9R2S4T6V8W0X1Y3Z5', false],
    'uuid · padded uuid' => ['uuid', ' 0199a7a4-6d5e-7c1b-9f3e-2b7c8d9e0f1a', false],
    'ulid · ulid' => ['ulid', '01K7Z3M8Q9R2S4T6V8W0X1Y3Z5', true],
    'ulid · int' => ['ulid', 1, false],
    'ulid · uuid' => ['ulid', '0199a7a4-6d5e-7c1b-9f3e-2b7c8d9e0f1a', false],
    'ulid · too long' => ['ulid', '01K7Z3M8Q9R2S4T6V8W0X1Y3Z5A', false],
]);

it('generates keys the shape check accepts', function (): void {
    config()->set('authentication.key_type', 'uuid');
    expect(DB::pretend(fn () => accountsOfUsers()->findByKey((string) Str::uuid7())))->toHaveCount(1);

    config()->set('authentication.key_type', 'ulid');
    expect(DB::pretend(fn () => accountsOfUsers()->findByKey((string) Str::ulid())))->toHaveCount(1);
});
