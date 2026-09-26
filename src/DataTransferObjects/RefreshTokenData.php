<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class RefreshTokenData
{
    public function __construct(
        #[SensitiveParameter] public string $refreshToken,
        public SessionContext $context,
    ) {}
}
