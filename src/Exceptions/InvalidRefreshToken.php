<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * A refresh token was unknown, expired, revoked, reused, minted for another guard, or its owner is disabled.
 */
final class InvalidRefreshToken extends AuthException
{
    public function errorCode(): string
    {
        return 'refresh_invalid';
    }

    public function status(): int
    {
        return 401;
    }
}
