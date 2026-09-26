<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\LoginStatus;

/**
 * `{"status": "challenge", "challenge_token": …, "remaining": [{"step", "methods"}]}`.
 * Not final: a documented extension point.
 *
 * @property PendingChallenge $resource
 */
class ChallengeResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $challenge = $this->resource;

        return [
            'status' => LoginStatus::ChallengeRequired->value,
            'challenge_token' => $challenge->token,
            'expires_at' => $challenge->expiresAt->toIso8601ZuluString(),
            'attempts_left' => $challenge->attemptsLeft,
            'method' => $challenge->method->value,
            'completed' => array_map(static fn (ChallengeStep $step): string => $step->value, $challenge->completed),
            'remaining' => array_map(static fn (ChallengeRequirement $requirement): array => $requirement->toStorage(), $challenge->remaining),
        ];
    }
}
