<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The outcome of a registration request.
 */
enum RegistrationStatus: string
{
    use Helpers;

    case Authenticated = 'authenticated';
    case VerificationRequired = 'verification_required';
    case Accepted = 'accepted';
}
