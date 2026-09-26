<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use Throwable;

/**
 * A factor submitted to a login challenge did not verify. The attempt was counted;
 * `attempts_left` tells the client how many remain before the challenge dies.
 */
final class ChallengeFactorFailed extends AuthException
{
    protected ?string $field = 'code';

    public static function withAttemptsLeft(int $attemptsLeft, ?Throwable $previous = null): self
    {
        $exception = new self($previous);
        $exception->extra['attempts_left'] = max(0, $attemptsLeft);

        return $exception;
    }

    public function attemptsLeft(): int
    {
        $left = $this->extra['attempts_left'] ?? 0;

        return is_int($left) ? $left : 0;
    }

    public function errorCode(): string
    {
        return 'factor_failed';
    }

    public function status(): int
    {
        return 422;
    }
}
