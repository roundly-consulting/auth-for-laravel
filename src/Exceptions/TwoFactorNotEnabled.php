<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * Two-factor authentication is not enabled for the account, so there is nothing to
 * disable and no recovery codes to replace.
 */
final class TwoFactorNotEnabled extends AuthException
{
    public function errorCode(): string
    {
        return 'two_factor_not_enabled';
    }

    public function status(): int
    {
        return 409;
    }
}
