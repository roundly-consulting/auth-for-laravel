<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The refresh token was rotated moments ago by a concurrent refresh of the same session
 * (inside `refresh-tokens.rotation.grace`), and the session lives on. The client should
 * keep the token the concurrent refresh handed out, not sign out, and retry the original
 * request once with it.
 */
final class RefreshSuperseded extends AuthException
{
    public function errorCode(): string
    {
        return 'refresh_superseded';
    }

    public function status(): int
    {
        return 409;
    }
}
