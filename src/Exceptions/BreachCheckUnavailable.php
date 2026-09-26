<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The breached-password service was unreachable and the guard fails closed.
 */
final class BreachCheckUnavailable extends AuthException
{
    protected ?string $field = 'password';

    public function errorCode(): string
    {
        return 'password_check_unavailable';
    }

    public function status(): int
    {
        return 503;
    }
}
