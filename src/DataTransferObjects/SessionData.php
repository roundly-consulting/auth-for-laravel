<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;

/**
 * One device session (a refresh-token family) as shown in a "your devices" list.
 */
final readonly class SessionData
{
    /**
     * @param  list<string>  $authMethods
     */
    public function __construct(
        public string $id,
        public ?string $deviceName,
        public ?string $ipAddress,
        public ?string $userAgent,
        public ?string $browser,
        public ?string $os,
        public ?string $deviceType,
        public ?string $country,
        public ?string $city,
        public array $authMethods,
        public CarbonImmutable $startedAt,
        public CarbonImmutable $lastUsedAt,
        public CarbonImmutable $expiresAt,
        public bool $current,
    ) {}
}
