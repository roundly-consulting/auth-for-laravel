<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use SensitiveParameter;

/**
 * The pending invitation behind a token — for an "accept your invitation" screen.
 * Unknown, expired, revoked, accepted and foreign-guard tokens are one uniform error.
 */
final readonly class PreviewInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $token): Invitation
    {
        if (! $this->guards->get($guard)->invitationsEnabled()) {
            throw new LoginMethodDisabled;
        }

        return Models::invitations()
            ->where('guard', $guard)
            ->where('token_hash', $this->hasher->link($guard, 'invitation', $token))
            ->pending(CarbonImmutable::now())
            ->first() ?? throw new InvalidInvitation;
    }
}
