<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * Internal: the address an invitation would create an account for is already in use.
 * Rolls the acceptance back; the client only ever sees the uniform `invalid_invitation`.
 */
final class InvitationAddressTaken extends AuthException
{
    public function errorCode(): string
    {
        return 'invalid_invitation';
    }

    public function status(): int
    {
        return 422;
    }
}
