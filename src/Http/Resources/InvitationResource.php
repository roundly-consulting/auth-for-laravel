<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\Models\Invitation;

/**
 * An invitation for admin screens. Not final: a documented extension point.
 *
 * @property Invitation $resource
 */
class InvitationResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $invitation = $this->resource;

        return [
            'id' => $invitation->getKey(),
            'email' => $invitation->email,
            'status' => $invitation->status()->value,
            'payload' => $invitation->payload ?? [],
            'locale' => $invitation->locale,
            'send_count' => $invitation->send_count,
            'last_sent_at' => $invitation->last_sent_at?->toIso8601ZuluString(),
            'expires_at' => $invitation->expires_at->toIso8601ZuluString(),
            'accepted_at' => $invitation->accepted_at?->toIso8601ZuluString(),
            'revoked_at' => $invitation->revoked_at?->toIso8601ZuluString(),
            'created_at' => $invitation->created_at?->toIso8601ZuluString(),
        ];
    }
}
