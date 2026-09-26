<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How an email address is verified: a link, or a short code typed back.
 */
enum VerificationChannel: string
{
    use Helpers;

    case Link = 'link';
    case Code = 'code';
}
