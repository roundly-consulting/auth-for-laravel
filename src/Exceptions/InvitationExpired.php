<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The invitation behind the token has expired (`invitations.distinct_errors`).
 */
final class InvitationExpired extends AuthException
{
    protected ?string $field = 'token';

    public function errorCode(): string
    {
        return 'invitation_expired';
    }

    public function status(): int
    {
        return 422;
    }
}
