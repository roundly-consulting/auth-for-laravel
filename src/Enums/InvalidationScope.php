<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Which of an account's sessions an invalidation reaches.
 */
enum InvalidationScope: string
{
    use Helpers;

    case None = 'none';
    case Others = 'others';
    case All = 'all';
}
