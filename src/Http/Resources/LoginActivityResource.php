<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\Models\LoginActivity;

/**
 * One row of the account's own login activity. The typed identifier, fingerprint and
 * internal ids are never exposed. Not final: a documented extension point.
 *
 * @property LoginActivity $resource
 */
class LoginActivityResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $activity = $this->resource;

        return [
            'type' => $activity->type->value,
            'outcome' => $activity->outcome->value,
            'method' => $activity->method,
            'ip_address' => $activity->ip_address,
            'user_agent' => $activity->user_agent,
            'country_code' => $activity->country_code,
            'city' => $activity->city,
            'new_device' => $activity->is_new_device,
            'session_id' => $activity->session_id,
            'created_at' => $activity->created_at?->toIso8601ZuluString(),
        ];
    }
}
