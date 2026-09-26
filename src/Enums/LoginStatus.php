<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The `status` of a login response: tokens were issued, or more steps are required.
 */
enum LoginStatus: string
{
    use Helpers;

    case Authenticated = 'authenticated';
    case ChallengeRequired = 'challenge';
}
