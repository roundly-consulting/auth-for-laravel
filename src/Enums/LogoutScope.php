<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Which sessions a logout ended.
 */
enum LogoutScope: string
{
    use Helpers;

    case Current = 'current';
    case Session = 'session';
    case Others = 'others';
    case Everywhere = 'everywhere';
}
