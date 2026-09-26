<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Models\Invitation;

/**
 * An invitation link was (re-)sent.
 */
final readonly class InvitationSent
{
    public function __construct(
        public string $guard,
        public Invitation $invitation,
    ) {}
}
