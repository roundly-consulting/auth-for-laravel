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
 * @property-read string $tokenType
 * @property-read string $accessToken
 * @property-read CarbonImmutable $accessExpiresAt
 * @property-read string $refreshToken
 * @property-read CarbonImmutable $refreshExpiresAt
 * @property-read string $sessionId
 */
class TokenPairResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array{status: 'authenticated', token_type: string, access_token: string, expires_in: int<0, max>, expires_at: string, refresh_token: string, refresh_expires_at: string, session_id: string}
     */
    public function toArray(Request $request): array
    {
        // Fields read through the resource (`$this->accessToken`) so OpenAPI generators type
        // them from the @property-read tags above.
        $expiresIn = (int) CarbonImmutable::now()->diffInSeconds($this->accessExpiresAt, false);

        return [
            'status' => LoginStatus::Authenticated->value,
            'token_type' => $this->tokenType,
            'access_token' => $this->accessToken,
            'expires_in' => $expiresIn > 0 ? $expiresIn : 0,
            'expires_at' => $this->accessExpiresAt->toIso8601ZuluString(),
            'refresh_token' => $this->refreshToken,
            'refresh_expires_at' => $this->refreshExpiresAt->toIso8601ZuluString(),
            'session_id' => $this->sessionId,
        ];
    }
}
