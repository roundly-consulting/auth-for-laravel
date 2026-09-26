<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The session is unknown or belongs to another account.
 */
final class SessionNotFound extends AuthException
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
