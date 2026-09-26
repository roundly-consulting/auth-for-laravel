<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The guard does not accept registrations.
 */
final class RegistrationClosed extends AuthException
{
    public function errorCode(): string
    {
        return 'registration_closed';
    }

    public function status(): int
    {
        return 403;
    }
}
