<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The invitation was mailed `invitations.max_sends` times. The count never resets, so no
 * later retry succeeds: revoke it and create a new one. Deliberately not a 429 — there is
 * no `Retry-After` worth waiting for.
 */
final class InvitationSendLimitReached extends AuthException
{
    public function errorCode(): string
    {
        return 'invitation_send_limit';
    }

    public function status(): int
    {
        return 422;
    }
}
