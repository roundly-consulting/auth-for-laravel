<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class VerificationData
{
    public function __construct(
        #[SensitiveParameter] public string $token,
        public ?string $email,
        public SessionContext $context,
    ) {}
}
