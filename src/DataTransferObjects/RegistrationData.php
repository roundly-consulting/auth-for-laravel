<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class RegistrationData
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        public string $email,
        #[SensitiveParameter] public ?string $password,
        public SessionContext $context,
        public array $attributes = [],
    ) {}
}
