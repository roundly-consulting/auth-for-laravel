<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Who may create an account on a guard.
 */
enum RegistrationMode: string
{
    use Helpers;

    case Open = 'open';
    case InviteOnly = 'invite_only';
    case Closed = 'closed';
}
