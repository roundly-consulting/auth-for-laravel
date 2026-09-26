<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The credentials did not verify. Uniform on purpose: unknown account, wrong password, passwordless account and (by default) risk denial all look alike.
 */
final class InvalidCredentials extends AuthException
{
    protected ?string $field = 'identifier';

    public function errorCode(): string
    {
        return 'invalid_credentials';
    }

    public function status(): int
    {
        return 422;
    }
}
