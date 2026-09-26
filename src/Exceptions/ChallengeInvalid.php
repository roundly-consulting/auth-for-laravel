<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * A login challenge token was unknown, expired, completed, invalidated, superseded, out of attempts or presented from another device.
 */
final class ChallengeInvalid extends AuthException
{
    protected ?string $field = 'challenge_token';

    public function errorCode(): string
    {
        return 'challenge_invalid';
    }

    public function status(): int
    {
        return 422;
    }
}
