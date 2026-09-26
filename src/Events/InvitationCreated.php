<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Models\Invitation;

/**
 * An invitation was created.
 */
final readonly class InvitationCreated
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Invitation $invitation,
    ) {}
}
