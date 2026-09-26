<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * A hash of random bytes, made once per process with the configured hashing driver, so
 * checking a password for an unknown or passwordless account costs exactly what a real
 * check costs — the response time never tells whether the account exists.
 */
final class DummyPasswordHash
{
    private static ?string $hash = null;

    public static function get(): string
    {
        return self::$hash ??= Hash::make(Token::urlSafe(40));
    }

    public static function flush(): void
    {
        self::$hash = null;
    }
}
