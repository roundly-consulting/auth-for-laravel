<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Notifications;

use RoundlyConsulting\Auth\Enums\NotificationType;

/**
 * A sign-in the risk assessment flagged (reaction `notify`) completed — the session is live.
 * Copy: `authentication::notifications.{type}.*`. Not final: swap it through
 * `notifications.classes`.
 */
class UnusualSignInNotification extends AuthenticationNotification
{
    public function type(): NotificationType
    {
        return NotificationType::UnusualSignIn;
    }
}
