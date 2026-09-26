<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use RoundlyConsulting\PackageToolkit\Contracts\HasRetryAfter;
use Throwable;

/**
 * A rate limit (or a hard account lock, which deliberately looks the same) was hit.
 * Renders 429 with a `Retry-After` header and a `retry_after` member.
 */
final class TooManyAttempts extends AuthException implements HasRetryAfter
{
    public static function retryAfter(int $seconds, ?Throwable $previous = null): self
    {
        $exception = new self($previous);
        $exception->extra['retry_after'] = max(1, $seconds);

        return $exception;
    }

    public function retryAfterSeconds(): int
    {
        $seconds = $this->extra['retry_after'] ?? 1;

        return is_int($seconds) ? $seconds : 1;
    }

    public function errorCode(): string
    {
        return 'too_many_attempts';
    }

    public function status(): int
    {
        return 429;
    }

    protected function headers(): array
    {
        return [...parent::headers(), 'Retry-After' => (string) $this->retryAfterSeconds()];
    }
}
