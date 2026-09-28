<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;

/**
 * Hard-locks an account for a while (default `lockout.duration`) and tells the owner —
 * exactly like the automatic lock after too many failed passwords. Existing sessions are
 * left alone — a lock stops new logins, it is not a logout.
 */
final readonly class LockAccount
{
    public function __construct(
        private GuardRegistry $guards,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, ?int $seconds = null): CarbonImmutable
    {
        $config = $this->guards->owning($guard, $account);
        $until = CarbonImmutable::now()->addSeconds(max(1, $seconds ?? $config->lockoutDuration()));

        AccountState::write($account, [Columns::lockedUntil() => $until, Columns::failedLoginCount() => 0]);

        event(new AccountLocked($guard, $account, $until));

        $this->notifications->send($config, NotificationType::AccountLocked, $account, new NotificationData($guard));

        return $until;
    }
}
