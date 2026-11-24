<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * An invitation was accepted with another address than the invited one (`invitations.reject_other_email`).
 * The invitation stays pending.
 */
final class InvitationEmailMismatch extends AuthException
{
    protected ?string $field = 'email';

    public function errorCode(): string
    {
        return 'invitation_email_mismatch';
    }

    public function status(): int
    {
        return 422;
    }
}
