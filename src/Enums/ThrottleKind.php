<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * A rate-limit bucket. Every key also carries the guard.
 */
enum ThrottleKind: string
{
    use Helpers;

    case Login = 'login';
    case LoginIp = 'login_ip';
    case LoginAccount = 'login_account';
    case EmailRequest = 'email_request';
    case EmailRequestIp = 'email_request_ip';
    case EmailRequestAccount = 'email_request_account';
    case Refresh = 'refresh';
    case Registration = 'registration';
    case Verification = 'verification';
    case Reauthentication = 'reauthentication';
}
