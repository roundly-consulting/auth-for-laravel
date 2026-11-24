<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The invitation behind the token was revoked (`invitations.distinct_errors`).
 */
final class InvitationRevoked extends AuthException
{
    protected ?string $field = 'token';

    public function errorCode(): string
    {
        return 'invitation_revoked';
    }

    public function status(): int
    {
        return 422;
    }
}
