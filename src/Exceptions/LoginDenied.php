<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * A risk assessment denied the login and the guard renders denials explicitly (`risk.deny_response = explicit`).
 */
final class LoginDenied extends AuthException
{
    public function errorCode(): string
    {
        return 'login_denied';
    }

    public function status(): int
    {
        return 403;
    }
}
