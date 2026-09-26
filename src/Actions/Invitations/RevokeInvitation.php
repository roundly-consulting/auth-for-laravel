<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Events\InvitationRevoked;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;

final class RevokeInvitation
{
    public function execute(Invitation $invitation): void
    {
        $revoked = Models::invitations()
            ->whereKey($invitation->getKey())
            ->whereNull('accepted_at')
            ->whereNull('revoked_at')
            ->update(['revoked_at' => CarbonImmutable::now()]);

        $invitation->refresh();

        if ($revoked > 0) {
            event(new InvitationRevoked($invitation->guard, $invitation));
        }
    }
}
