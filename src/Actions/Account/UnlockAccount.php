<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Events\AccountUnlocked;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Actors;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Lifts a hard lock and resets the failed-password counter. `$actor` (the admin) goes on
 * the event; no notification is sent.
 */
final readonly class UnlockAccount
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, ?Model $actor = null): void
    {
        $this->guards->owning($guard, $account);
        $actor = Actors::other($account, $actor);

        AccountState::write($account, [Columns::lockedUntil() => null, Columns::failedLoginCount() => 0]);

        event(new AccountUnlocked($guard, $account, $actor));
    }
}
