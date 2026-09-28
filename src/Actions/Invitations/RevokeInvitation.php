<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Events\InvitationRevoked;
use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Revokes a pending invitation (its link dies); idempotent for one already revoked or
 * accepted. Another guard's invitation is unknown here ({@see InvitationNotFound}).
 */
final class RevokeInvitation
{
    public function execute(string $guard, Invitation $invitation): void
    {
        if ($invitation->guard !== $guard) {
            throw new InvitationNotFound;
        }

        $revoked = Models::invitations()
            ->whereKey($invitation->getKey())
            ->where('guard', $guard)
            ->whereNull('accepted_at')
            ->whereNull('revoked_at')
            ->update(['revoked_at' => CarbonImmutable::now()]);

        $invitation->refresh();

        if ($revoked > 0) {
            event(new InvitationRevoked($invitation->guard, $invitation));
        }
    }
}
