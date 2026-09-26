<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * Two-factor authentication cannot be disabled while the guard requires it.
 */
final class TwoFactorRequired extends AuthException
{
    public function errorCode(): string
    {
        return 'two_factor_required';
    }

    public function status(): int
    {
        return 409;
    }
}
