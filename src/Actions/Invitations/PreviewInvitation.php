<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationAlreadyAccepted;
use RoundlyConsulting\Auth\Exceptions\InvitationExpired;
use RoundlyConsulting\Auth\Exceptions\InvitationRevoked;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use SensitiveParameter;

/**
 * The pending invitation behind a token — for an "accept your invitation" screen.
 * Unknown, expired, revoked, accepted and foreign-guard tokens are one uniform error —
 * unless `invitations.distinct_errors`: then a known token's dead invitation answers why
 * (`invitation_accepted`, `invitation_revoked`, `invitation_expired`). Unknown tokens, and
 * links a newer send replaced (each send stores a new hash), stay `invalid_invitation`.
 */
final readonly class PreviewInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $token): Invitation
    {
        $config = $this->guards->get($guard);

        if (! $config->invitationsEnabled()) {
            throw new LoginMethodDisabled;
        }

        $hash = $this->hasher->link($guard, 'invitation', $token);
        $now = CarbonImmutable::now();

        $invitation = Models::invitations()
            ->where('guard', $guard)
            ->where('token_hash', $hash)
            ->pending($now)
            ->first();

        if ($invitation !== null) {
            return $invitation;
        }

        if (! $config->invitationDistinctErrors()) {
            throw new InvalidInvitation;
        }

        throw $this->reason(Models::invitations()->where('guard', $guard)->where('token_hash', $hash)->first(), $now);
    }

    private function reason(?Invitation $invitation, CarbonImmutable $now): AuthException
    {
        return match (true) {
            $invitation === null => new InvalidInvitation,
            $invitation->accepted_at !== null => new InvitationAlreadyAccepted,
            $invitation->revoked_at !== null => new InvitationRevoked,
            $invitation->expires_at <= $now => new InvitationExpired,
            default => new InvalidInvitation,
        };
    }
}
