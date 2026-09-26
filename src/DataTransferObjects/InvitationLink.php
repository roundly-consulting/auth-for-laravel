<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Models\Invitation;
use SensitiveParameter;

/**
 * Returned once per send, so an admin UI may also show a copyable link. The plaintext
 * is never stored or logged.
 */
final readonly class InvitationLink
{
    public function __construct(
        public Invitation $invitation,
        #[SensitiveParameter] public string $token,
        #[SensitiveParameter] public string $url,
    ) {}
}
