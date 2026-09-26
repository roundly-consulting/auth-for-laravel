<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\SessionData;

/**
 * One device session. Not final: a documented extension point.
 *
 * @property SessionData $resource
 */
class SessionResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $session = $this->resource;

        return [
            'id' => $session->id,
            'device_name' => $session->deviceName,
            'ip_address' => $session->ipAddress,
            'user_agent' => $session->userAgent,
            'browser' => $session->browser,
            'os' => $session->os,
            'device_type' => $session->deviceType,
            'country' => $session->country,
            'city' => $session->city,
            'auth_methods' => $session->authMethods,
            'started_at' => $session->startedAt->toIso8601ZuluString(),
            'last_used_at' => $session->lastUsedAt->toIso8601ZuluString(),
            'expires_at' => $session->expiresAt->toIso8601ZuluString(),
            'current' => $session->current,
        ];
    }
}
