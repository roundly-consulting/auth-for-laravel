<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How an authentication attempt ended.
 */
enum ActivityOutcome: string
{
    use Helpers;

    case Succeeded = 'succeeded';
    case Challenged = 'challenged';
    case FailedCredentials = 'failed_credentials';
    case FailedFactor = 'failed_factor';
    case FailedToken = 'failed_token';
    case Throttled = 'throttled';
    case Locked = 'locked';
    case Disabled = 'disabled';
    case Unverified = 'unverified';
    case Denied = 'denied';
    case FingerprintMismatch = 'fingerprint_mismatch';
    case Expired = 'expired';
    case Replayed = 'replayed';
}
