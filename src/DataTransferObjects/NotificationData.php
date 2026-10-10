<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use SensitiveParameter;

/**
 * What every authentication notification is built from. `replacements` are the
 * translation placeholders of the notification's copy (a dictionary, not a shape).
 * `actor` is who acted when it was not the account itself (a host passed `actor:`); an
 * actor-aware type then renders its `by_actor` copy.
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
        public ?ActorData $actor = null,
    ) {}
}
