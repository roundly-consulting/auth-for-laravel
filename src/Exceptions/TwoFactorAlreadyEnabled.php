<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * Two-factor authentication is already enabled for the account.
 */
final class TwoFactorAlreadyEnabled extends AuthException
{
    public function errorCode(): string
    {
        return 'two_factor_already_enabled';
    }

    public function status(): int
    {
        return 409;
    }
}
