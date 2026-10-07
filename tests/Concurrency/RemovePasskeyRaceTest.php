<?php

declare(strict_types=1);

use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Exceptions\LastCredential;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use RoundlyConsulting\Testing\Fixtures\LockRecorder;
use RoundlyConsulting\Testing\Fixtures\LockRecordingGrammar;

/**
 * Two removes on one account, where passkeys are the only way in: the last-credential
 * check (a count over the passkeys) and the revoke must see each other. The passkeys are
 * separate rows, so only the shared account row can serialise them.
 */
beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['login.password' => false, 'login.magic_link' => false, 'login.email_otp' => false]);

    // SQLite compiles lockForUpdate() to nothing; this grammar leaves a marker instead.
    $connection = DB::connection();

    if ($connection instanceof Connection && $connection->getDriverName() === 'sqlite') {
        $connection->setQueryGrammar(new LockRecordingGrammar($connection));
    }

    LockRecorder::flush();
    LockRecorder::listenForMarkers();
});

function locksAccountRow(QueryExecuted $query): bool
{
    return str_contains($query->sql, (new User)->getTable())
        && preg_match('/\bfor update\b|lock-for-update/i', $query->sql) === 1;
}

it('lets only one of two concurrent removes take the last way in', function (): void {
    $user = User::factory()->create();
    $first = addPasskey($user);
    $second = addPasskey($user);
    $outcomes = [];
    $locked = false;
    $raced = false;

    $removeSecond = static function () use ($user, $second, &$outcomes): void {
        try {
            Authentication::passkeys()->remove(User::query()->findOrFail($user->getKey()), (int) $second->getKey());
            $outcomes[] = 'removed';
        } catch (LastCredential) {
            $outcomes[] = 'last_credential';
        }
    };

    DB::listen(static function (QueryExecuted $query) use (&$locked, &$raced, $removeSecond): void {
        if (locksAccountRow($query)) {
            $locked = true;

            return;
        }

        if ($raced || ! str_contains($query->sql, 'count(*)') || ! str_contains($query->sql, (new Passkey)->getTable())) {
            return;
        }

        $raced = true;

        // The second remove arrives while the first sits between its count and its revoke.
        // A first remove holding the account row FOR UPDATE makes it wait for the commit
        // (as the engine would); without the lock it runs right now.
        $locked && $query->connection->transactionLevel() > 0
            ? $query->connection->afterCommit($removeSecond)
            : $removeSecond();
    });

    $result = Authentication::passkeys()->remove($user, (int) $first->getKey());

    expect($result)->toBeNull()
        ->and($raced)->toBeTrue()
        ->and($outcomes)->toBe(['last_credential'])
        ->and($user->passkeys()->count())->toBe(1);
});

it('takes the account row lock inside the transaction', function (): void {
    $user = User::factory()->create();
    $first = addPasskey($user);
    addPasskey($user);

    Authentication::passkeys()->remove($user, (int) $first->getKey());

    $locks = LockRecorder::recorded();

    expect($locks)->toHaveCount(1)
        ->and($locks[0]['marker'])->toBe('lock-for-update')
        ->and($locks[0]['transactionDepth'])->toBe(1)
        ->and($locks[0]['sql'])->toContain('"'.(new User)->getTable().'"');
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'the recording grammar is SQLite\'s; a real engine takes the lock itself');
