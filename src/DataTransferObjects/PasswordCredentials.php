<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class PasswordCredentials
{
    public function __construct(
        public string $identifier,
        #[SensitiveParameter] public string $password,
    ) {}
}
