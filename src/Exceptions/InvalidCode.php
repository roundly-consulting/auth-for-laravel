<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use Throwable;

/**
 * A short emailed/typed code did not verify. `attempts_left` is only ever added on
 * authenticated, challenge and re-authentication paths: on the guest email-OTP and
 * verification endpoints a decrementing counter for real addresses (vs a constant one
 * for unknown addresses) would enumerate accounts.
 */
final class InvalidCode extends AuthException
{
    protected ?string $field = 'code';

    public static function withAttemptsLeft(int $attemptsLeft, ?Throwable $previous = null): self
    {
        $exception = new self($previous);
        $exception->extra['attempts_left'] = max(0, $attemptsLeft);

        return $exception;
    }

    public function errorCode(): string
    {
        return 'invalid_code';
    }

    public function status(): int
    {
        return 422;
    }
}
