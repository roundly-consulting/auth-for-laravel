<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class AcceptInvitationData
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        #[SensitiveParameter] public string $token,
        #[SensitiveParameter] public ?string $password,
        public SessionContext $context,
        public array $attributes = [],
        public ?string $email = null,
    ) {}
}
