<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Events\AccountUnlocked;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;

final readonly class UnlockAccount
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account): void
    {
        $this->guards->get($guard);

        AccountState::write($account, [Columns::lockedUntil() => null, Columns::failedLoginCount() => 0]);

        event(new AccountUnlocked($guard, $account));
    }
}
