<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class CodeData
{
    public function __construct(
        #[SensitiveParameter] public string $code,
        public SessionContext $context,
    ) {}
}
