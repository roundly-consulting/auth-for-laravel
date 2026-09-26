<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The submitted factor cannot satisfy the current step (or is not allowed for this account).
 */
final class FactorNotAllowed extends AuthException
{
    protected ?string $field = 'method';

    public function errorCode(): string
    {
        return 'factor_not_allowed';
    }

    public function status(): int
    {
        return 422;
    }
}
