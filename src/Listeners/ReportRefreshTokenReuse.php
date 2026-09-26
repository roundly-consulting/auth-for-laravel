<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Listeners;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\RefreshTokenReuseReported;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;

/**
 * refresh-tokens already killed the family; this re-emits the signal with the guard and
 * account resolved, and tells the owner.
 */
final readonly class ReportRefreshTokenReuse
{
    public function __construct(
        private GuardRegistry $guards,
        private NotificationDispatcher $notifications,
    ) {}

    public function handle(RefreshTokenReuseDetected $event): void
    {
        $guard = $this->guards->forMorphClass($event->ownerType);

        if ($guard === null) {
            return;
        }

        $account = (new AccountRepository($guard))->findByKey($event->ownerId);

        if (! $account instanceof Account) {
            return;
        }

        event(new RefreshTokenReuseReported($guard->name(), $account, $event->familyId));

        $this->notifications->send($guard, NotificationType::RefreshTokenReuse, $account, new NotificationData(
            guard: $guard->name(),
            replacements: ['reason' => 'refresh_token_reuse'],
        ));
    }
}
