<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The passkey registration response did not verify (or the credential is already registered).
 */
final class PasskeyRegistrationFailed extends AuthException
{
    protected ?string $field = 'credential';

    public function errorCode(): string
    {
        return 'passkey_registration_failed';
    }

    public function status(): int
    {
        return 422;
    }
}
