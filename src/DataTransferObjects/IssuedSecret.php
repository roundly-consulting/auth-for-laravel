<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Models\OneTimeToken;
use SensitiveParameter;

/**
 * A freshly issued one-time secret. The plaintext token (links) or code (codes) is
 * returned exactly once and only ever lands in the notification.
 */
final readonly class IssuedSecret
{
    public function __construct(
        public OneTimeToken $record,
        #[SensitiveParameter] public ?string $token = null,
        #[SensitiveParameter] public ?string $code = null,
    ) {}
}
