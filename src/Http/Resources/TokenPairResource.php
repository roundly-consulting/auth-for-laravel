<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\LoginStatus;

/**
 * `{"status": "authenticated", "token_type": "Bearer", "access_token": …, …}` — not
 * wrapped in `data`. Not final: a documented extension point.
 *
 * @property TokenPair $resource
 */
class TokenPairResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $pair = $this->resource;

        return [
            'status' => LoginStatus::Authenticated->value,
            'token_type' => $pair->tokenType,
            'access_token' => $pair->accessToken,
            'expires_in' => max(0, (int) CarbonImmutable::now()->diffInSeconds($pair->accessExpiresAt, false)),
            'expires_at' => $pair->accessExpiresAt->toIso8601ZuluString(),
            'refresh_token' => $pair->refreshToken,
            'refresh_expires_at' => $pair->refreshExpiresAt->toIso8601ZuluString(),
            'session_id' => $pair->sessionId,
        ];
    }
}
