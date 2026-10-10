<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Actors;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;

/**
 * Hard-locks an account for a while (default `lockout.duration`) and tells the owner —
 * like the automatic lock after too many failed passwords. Existing sessions are
 * left alone — a lock stops new logins, it is not a logout. Pass the admin as `$actor`
 * and the owner is told an administrator locked it (the `by_actor` copy).
 */
final readonly class LockAccount
{
    public function __construct(
        private GuardRegistry $guards,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, ?int $seconds = null, ?Model $actor = null): CarbonImmutable
    {
        $config = $this->guards->owning($guard, $account);
        $actor = Actors::other($account, $actor);
        $data = new NotificationData($guard, actor: Actors::reference($actor));
        $until = CarbonImmutable::now()->addSeconds(max(1, $seconds ?? $config->lockoutDuration()));

        AccountState::write($account, [Columns::lockedUntil() => $until, Columns::failedLoginCount() => 0]);

        event(new AccountLocked($guard, $account, $until, $actor));

        $this->notifications->send($config, NotificationType::AccountLocked, $account, $data);

        return $until;
    }
}
