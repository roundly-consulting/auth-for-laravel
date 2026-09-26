<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Models\Invitation;

/**
 * An invitation link was (re-)sent.
 */
final readonly class InvitationSent
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Invitation $invitation,
    ) {}
}
