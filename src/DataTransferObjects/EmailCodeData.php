<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class EmailCodeData
{
    public function __construct(
        public string $email,
        #[SensitiveParameter] public string $code,
        public SessionContext $context,
    ) {}
}
