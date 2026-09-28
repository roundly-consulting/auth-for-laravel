<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationLink;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;

/**
 * Re-sends a pending invitation (a fresh link; the old one dies), within the guard's
 * `resend_cooldown` and `max_sends`. Another guard's invitation is unknown here
 * ({@see InvitationNotFound}).
 */
final readonly class ResendInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private SendInvitation $send,
    ) {}

    public function execute(string $guard, Invitation $invitation): InvitationLink
    {
        if ($invitation->guard !== $guard) {
            throw new InvitationNotFound;
        }

        $config = $this->guards->get($guard);
        $now = CarbonImmutable::now();

        if (! $invitation->isPending($now)) {
            throw new InvalidInvitation;
        }

        if ($invitation->send_count >= $config->invitationMaxSends()) {
            throw TooManyAttempts::retryAfter($config->invitationTtl());
        }

        $available = $invitation->last_sent_at?->addSeconds($config->invitationResendCooldown());

        if ($available !== null && $available->greaterThan($now)) {
            throw TooManyAttempts::retryAfter((int) $now->diffInSeconds($available));
        }

        return $this->send->execute($guard, $invitation);
    }
}
