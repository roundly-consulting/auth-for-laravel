<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;

/**
 * What an invitee may see before accepting: the address, the guard, the expiry, and
 * only the payload keys listed in `invitations.preview_payload_keys`. Not final: a
 * documented extension point.
 *
 * @property Invitation $resource
 */
class InvitationPreviewResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $invitation = $this->resource;
        $keys = app(GuardRegistry::class)->get($invitation->guard)->invitationPreviewPayloadKeys();

        return [
            'email' => $invitation->email,
            'guard' => $invitation->guard,
            'expires_at' => $invitation->expires_at->toIso8601ZuluString(),
            'payload' => array_intersect_key($invitation->payload ?? [], array_flip($keys)),
        ];
    }
}
