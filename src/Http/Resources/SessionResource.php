<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\SessionData;

/**
 * One device session. Not final: a documented extension point.
 *
 * @property SessionData $resource
 * @property-read string $id
 * @property-read string|null $deviceName
 * @property-read string|null $ipAddress
 * @property-read string|null $userAgent
 * @property-read string|null $browser
 * @property-read string|null $os
 * @property-read string|null $deviceType
 * @property-read string|null $country
 * @property-read string|null $city
 * @property-read list<string> $authMethods
 * @property-read CarbonImmutable $startedAt
 * @property-read CarbonImmutable $lastUsedAt
 * @property-read CarbonImmutable $expiresAt
 * @property-read bool $current
 */
class SessionResource extends JsonResource
{
    /**
     * @return array{id: string, device_name: string|null, ip_address: string|null, user_agent: string|null, browser: string|null, os: string|null, device_type: string|null, country: string|null, city: string|null, auth_methods: list<string>, started_at: string, last_used_at: string, expires_at: string, current: bool}
     */
    public function toArray(Request $request): array
    {
        // Read through the resource so OpenAPI generators type the fields from @property-read.
        return [
            'id' => $this->id,
            'device_name' => $this->deviceName,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'browser' => $this->browser,
            'os' => $this->os,
            'device_type' => $this->deviceType,
            'country' => $this->country,
            'city' => $this->city,
            'auth_methods' => $this->authMethods,
            'started_at' => $this->startedAt->toIso8601ZuluString(),
            'last_used_at' => $this->lastUsedAt->toIso8601ZuluString(),
            'expires_at' => $this->expiresAt->toIso8601ZuluString(),
            'current' => $this->current,
        ];
    }
}
