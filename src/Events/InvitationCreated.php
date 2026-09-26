<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Models\Invitation;

/**
 * An invitation was created.
 */
final readonly class InvitationCreated
{
    public function __construct(
        public string $guard,
        public Invitation $invitation,
    ) {}
}
