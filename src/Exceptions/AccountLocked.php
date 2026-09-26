<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use RoundlyConsulting\PackageToolkit\Contracts\HasRetryAfter;
use Throwable;

/**
 * The account is hard-locked (opt-in lockout) and the caller is already authenticated,
 * so revealing the lock confirms nothing. Login paths answer a lock with
 * {@see TooManyAttempts} instead, so a correct password is never confirmed.
 */
final class AccountLocked extends AuthException implements HasRetryAfter
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
        return 'account_locked';
    }

    public function status(): int
    {
        return 423;
    }

    protected function headers(): array
    {
        return [...parent::headers(), 'Retry-After' => (string) $this->retryAfterSeconds()];
    }
}
