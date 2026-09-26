<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Models\Invitation;

/**
 * An invitation was accepted and its account created. Read `$invitation->payload` to assign roles.
 */
final readonly class InvitationAccepted
{
    public function __construct(
        public string $guard,
        public Invitation $invitation,
        public Account $account,
    ) {}
}
