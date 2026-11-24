<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The invitation behind the token was already accepted (`invitations.distinct_errors`).
 */
final class InvitationAlreadyAccepted extends AuthException
{
    protected ?string $field = 'token';

    public function errorCode(): string
    {
        return 'invitation_accepted';
    }

    public function status(): int
    {
        return 422;
    }
}
