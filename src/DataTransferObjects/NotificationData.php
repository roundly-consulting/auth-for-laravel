<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use SensitiveParameter;

/**
 * What every authentication notification is built from. `replacements` are the
 * translation placeholders of the notification's copy (a dictionary, not a shape).
 */
final readonly class NotificationData
{
    /**
     * @param  array<string, string|int>  $replacements
     */
    public function __construct(
        public string $guard,
        #[SensitiveParameter] public ?string $url = null,
        #[SensitiveParameter] public ?string $code = null,
        public ?CarbonImmutable $expiresAt = null,
        public array $replacements = [],
    ) {}
}
