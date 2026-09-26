<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;

final readonly class PasskeyRegistrationData
{
    public function __construct(
        public RegistrationResponseData $response,
        public ?string $name,
        public SessionContext $context,
    ) {}
}
