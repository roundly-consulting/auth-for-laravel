<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class ChangePasswordData
{
    public function __construct(
        #[SensitiveParameter] public ?string $currentPassword,
        #[SensitiveParameter] public string $newPassword,
        public CurrentToken $current,
        public SessionContext $context,
    ) {}
}
