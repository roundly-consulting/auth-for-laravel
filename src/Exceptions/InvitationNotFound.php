<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The invitation is unknown or belongs to another guard.
 */
final class InvitationNotFound extends AuthException
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
