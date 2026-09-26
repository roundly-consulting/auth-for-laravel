<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The account's email address must be verified first.
 */
final class EmailNotVerified extends AuthException
{
    public function errorCode(): string
    {
        return 'email_not_verified';
    }

    public function status(): int
    {
        return 403;
    }
}
