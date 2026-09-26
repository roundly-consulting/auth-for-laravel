<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use Throwable;

/**
 * A sensitive action needs a recent re-authentication. `methods` lists what this
 * account may re-authenticate with.
 */
final class ReauthenticationRequired extends AuthException
{
    /**
     * @param  list<ReauthenticationMethod>  $methods
     */
    public static function using(array $methods, ?Throwable $previous = null): self
    {
        $exception = new self($previous);
        $exception->extra['methods'] = array_map(static fn (ReauthenticationMethod $method): string => $method->value, $methods);

        return $exception;
    }

    public function errorCode(): string
    {
        return 'reauthentication_required';
    }

    public function status(): int
    {
        return 403;
    }
}
