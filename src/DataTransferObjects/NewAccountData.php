<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Contracts\CreatesAccounts;
use SensitiveParameter;

/**
 * What a {@see CreatesAccounts} receives.
 * `attributes` is the host-validated pass-through payload, already allow-listed by the
 * host's registration rules.
 */
final readonly class NewAccountData
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        public string $email,
        #[SensitiveParameter] public ?string $password,
        public ?string $locale = null,
        public ?string $timezone = null,
        public bool $emailVerified = false,
        public array $attributes = [],
    ) {}
}
