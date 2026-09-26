<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The feature is turned off for this guard, so the endpoint behaves as absent.
 */
final class LoginMethodDisabled extends AuthException
{
    public function errorCode(): string
    {
        return 'method_disabled';
    }

    public function status(): int
    {
        return 404;
    }
}
