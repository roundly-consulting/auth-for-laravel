<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Notifications;

use RoundlyConsulting\Auth\Enums\NotificationType;

/**
 * A sign-in was refused by the risk reaction `deny` — no session was created.
 * Copy: `authentication::notifications.{type}.*`. Not final: swap it through
 * `notifications.classes`.
 */
class SignInBlockedNotification extends AuthenticationNotification
{
    public function type(): NotificationType
    {
        return NotificationType::SignInBlocked;
    }
}
