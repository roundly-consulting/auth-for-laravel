<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The account is disabled. Only revealed after a verified first factor.
 */
final class AccountDisabled extends AuthException
{
    public function errorCode(): string
    {
        return 'account_disabled';
    }

    public function status(): int
    {
        return 403;
    }
}
