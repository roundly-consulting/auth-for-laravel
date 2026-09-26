<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * The opt-in hard lock. The counter is only ever touched when `lockout.enabled`, and
 * only through a bounded conditional increment (`… WHERE count < threshold`), so an
 * attacker can neither overflow the column nor cause a write per attempt on guards
 * that do not use it. A lock never revokes existing sessions — an attacker can trigger
 * one, and it must not log the victim out.
 */
final readonly class Lockout
{
    public function __construct(private NotificationDispatcher $notifications) {}

    /**
     * Count a failed password; true when this failure locked the account.
     */
    public function recordFailure(GuardConfig $guard, Account $account): bool
    {
        if (! $guard->lockoutEnabled() || $account->isLocked()) {
            return false;
        }

        $model = AccountModels::of($account);
        $column = Columns::failedLoginCount();
        $threshold = $guard->lockoutThreshold();

        $model->newQuery()->whereKey($model->getKey())->where($column, '<', $threshold)->increment($column);

        $count = (int) $model->newQuery()->whereKey($model->getKey())->value($column);

        if ($count < $threshold) {
            AccountState::write($account, [$column => $count]);

            return false;
        }

        $until = CarbonImmutable::now()->addSeconds($guard->lockoutDuration());

        AccountState::write($account, [$column => 0, Columns::lockedUntil() => $until]);

        event(new AccountLocked($guard->name(), $account, $until));

        $this->notifications->send($guard, NotificationType::AccountLocked, $account, new NotificationData($guard->name()));

        return true;
    }

    /**
     * Seconds until a hard lock lapses (at least 1).
     */
    public static function secondsRemaining(Account $account): int
    {
        $until = AccountModels::of($account)->getAttribute(Columns::lockedUntil());

        return $until instanceof DateTimeInterface ? max(1, (int) CarbonImmutable::now()->diffInSeconds($until, false)) : 1;
    }

    public function reset(GuardConfig $guard, Account $account): void
    {
        if (! $guard->lockoutEnabled()) {
            return;
        }

        $model = AccountModels::of($account);

        if ((int) $model->getAttribute(Columns::failedLoginCount()) !== 0) {
            AccountState::write($account, [Columns::failedLoginCount() => 0]);
        }
    }
}
