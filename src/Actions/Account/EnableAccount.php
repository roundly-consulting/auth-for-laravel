<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Events\AccountEnabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Actors;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Enables a disabled account again. `$actor` (the admin) goes on the event; no
 * notification is sent.
 */
final readonly class EnableAccount
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, ?Model $actor = null): void
    {
        $this->guards->owning($guard, $account);
        $actor = Actors::other($account, $actor);

        AccountState::write($account, [Columns::disabledAt() => null, Columns::disabledReason() => null]);

        event(new AccountEnabled($guard, $account, $actor));
    }
}
