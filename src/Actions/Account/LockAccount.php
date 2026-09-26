<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Hard-locks an account for a while (default `lockout.duration`). Existing sessions are
 * left alone — a lock stops new logins, it is not a logout.
 */
final readonly class LockAccount
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, ?int $seconds = null): CarbonImmutable
    {
        $until = CarbonImmutable::now()->addSeconds(max(1, $seconds ?? $this->guards->get($guard)->lockoutDuration()));

        AccountState::write($account, [Columns::lockedUntil() => $until, Columns::failedLoginCount() => 0]);

        event(new AccountLocked($guard, $account, $until));

        return $until;
    }
}
