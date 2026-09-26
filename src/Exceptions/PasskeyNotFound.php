<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The passkey is unknown or belongs to another account.
 */
final class PasskeyNotFound extends AuthException
{
    public function errorCode(): string
    {
        return 'not_found';
    }

    public function status(): int
    {
        return 404;
    }
}
