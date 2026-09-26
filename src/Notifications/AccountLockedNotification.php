<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Notifications;

use RoundlyConsulting\Auth\Enums\NotificationType;

/**
 * Copy: `authentication::notifications.{type}.*`. Not final: swap it through
 * `notifications.classes`.
 */
class AccountLockedNotification extends AuthenticationNotification
{
    public function type(): NotificationType
    {
        return NotificationType::AccountLocked;
    }
}
