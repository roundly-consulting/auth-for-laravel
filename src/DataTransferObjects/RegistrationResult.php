<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\RegistrationStatus;

/**
 * `login` is set only for `Authenticated` — and may itself be a challenge. The
 * enumeration-safe statuses never expose the account.
 */
final readonly class RegistrationResult
{
    public function __construct(
        public RegistrationStatus $status,
        public ?LoginResult $login = null,
    ) {}
}
