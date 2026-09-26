<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * An invitation token was unknown, expired, revoked, already accepted, or its address is already taken.
 */
final class InvalidInvitation extends AuthException
{
    protected ?string $field = 'token';

    public function errorCode(): string
    {
        return 'invalid_invitation';
    }

    public function status(): int
    {
        return 422;
    }
}
