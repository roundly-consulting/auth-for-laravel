<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationLink;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Exceptions\InvitationSendLimitReached;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Re-sends a pending invitation (a fresh link; the old one dies), within the guard's
 * `resend_cooldown` ({@see TooManyAttempts}, with the seconds left) and `max_sends`
 * ({@see InvitationSendLimitReached} — final, the count never resets). Another guard's
 * invitation is unknown here ({@see InvitationNotFound}).
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
            throw new InvitationSendLimitReached;
        }

        $cooldown = $config->invitationResendCooldown();
        $available = $invitation->last_sent_at?->addSeconds($cooldown);

        if ($available !== null && $available->greaterThan($now)) {
            throw TooManyAttempts::retryAfter((int) $now->diffInSeconds($available));
        }

        // Reserve the window atomically: of two resends that both passed the check above,
        // one moves `last_sent_at` and the other finds the cooldown running.
        if ($cooldown > 0) {
            $reserved = Models::invitations()->whereKey($invitation->getKey())->where('guard', $guard)
                ->where(static fn (Builder $query): Builder => $query->whereNull('last_sent_at')->orWhere('last_sent_at', '<=', $now->subSeconds($cooldown)))
                ->update(['last_sent_at' => $now]);

            if ($reserved === 0) {
                $available = $invitation->refresh()->last_sent_at?->addSeconds($cooldown);

                throw TooManyAttempts::retryAfter($available === null ? $cooldown : (int) $now->diffInSeconds($available));
            }
        }

        return $this->send->execute($guard, $invitation);
    }
}
