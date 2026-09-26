<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class TokenData
{
    public function __construct(
        #[SensitiveParameter] public string $token,
        public SessionContext $context,
    ) {}
}
