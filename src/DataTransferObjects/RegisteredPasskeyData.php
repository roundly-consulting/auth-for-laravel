<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Passkeys\Models\Passkey;

final readonly class RegisteredPasskeyData
{
    public function __construct(
        public Passkey $passkey,
        public ?TokenPair $tokens = null,
    ) {}
}
