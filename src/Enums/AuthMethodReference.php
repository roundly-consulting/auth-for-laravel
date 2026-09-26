<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * RFC 8176 `amr` values carried by access tokens. `email` is non-RFC: possession of a mailbox (magic link, invitation, reset link).
 */
enum AuthMethodReference: string
{
    use Helpers;

    case Pwd = 'pwd';
    case Otp = 'otp';
    case Email = 'email';
    case Hwk = 'hwk';
    case User = 'user';
    case Mfa = 'mfa';

    /**
     * @param  list<self>  $methods
     * @return list<string>
     */
    public static function toValues(array $methods): array
    {
        return array_values(array_unique(array_map(static fn (self $method): string => $method->value, $methods)));
    }

    /**
     * Parse stored `amr` values back into cases, dropping anything unknown.
     *
     * @return list<self>
     */
    public static function fromValues(mixed $values): array
    {
        if (! is_array($values)) {
            return [];
        }

        $methods = [];

        foreach ($values as $value) {
            $method = is_string($value) ? self::tryFrom($value) : null;

            if ($method !== null && ! in_array($method, $methods, true)) {
                $methods[] = $method;
            }
        }

        return $methods;
    }
}
