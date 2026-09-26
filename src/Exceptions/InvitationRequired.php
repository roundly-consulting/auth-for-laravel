<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The guard only accepts registrations through an invitation.
 */
final class InvitationRequired extends AuthException
{
    public function errorCode(): string
    {
        return 'invitation_required';
    }

    public function status(): int
    {
        return 403;
    }
}
