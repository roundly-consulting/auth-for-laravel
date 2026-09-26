<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * An unknown guard name was used — there is no `authentication.guards.<name>` entry.
 */
final class GuardNotConfigured extends AuthenticationMisconfigured
{
    public static function named(string $guard): self
    {
        return self::because("The authentication guard [{$guard}] is not configured in authentication.guards.");
    }
}
