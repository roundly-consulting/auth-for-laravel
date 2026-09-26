<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How authentication notifications are delivered.
 */
enum NotificationDelivery: string
{
    use Helpers;

    case Sync = 'sync';
    case AfterResponse = 'after_response';
    case Queue = 'queue';
}
