<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * Removing the credential would leave the account without a way to sign in (or violate a required policy).
 */
final class LastCredential extends AuthException
{
    public function errorCode(): string
    {
        return 'last_credential';
    }

    public function status(): int
    {
        return 409;
    }
}
