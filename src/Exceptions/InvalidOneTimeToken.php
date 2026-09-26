<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * An emailed link was unknown, expired, consumed, invalidated or minted for another guard or purpose — deliberately indistinguishable.
 */
final class InvalidOneTimeToken extends AuthException
{
    protected ?string $field = 'token';

    public function errorCode(): string
    {
        return 'invalid_token';
    }

    public function status(): int
    {
        return 422;
    }
}
