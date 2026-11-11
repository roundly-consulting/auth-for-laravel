<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\LoginStatus;

/**
 * `{"status": "challenge", "challenge_token": …, "remaining": [{"step", "methods"}]}`.
 * Not final: a documented extension point.
 *
 * @property PendingChallenge $resource
 * @property-read string $token
 * @property-read CarbonImmutable $expiresAt
 * @property-read LoginMethod $method
 * @property-read int $attemptsLeft
 */
class ChallengeResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array{status: 'challenge', challenge_token: string, expires_at: string, attempts_left: int, method: value-of<LoginMethod>, completed: list<value-of<ChallengeStep>>, remaining: list<array{step: value-of<ChallengeStep>, methods: list<value-of<FactorMethod>>}>}
     */
    public function toArray(Request $request): array
    {
        // Fields read through the resource (`$this->token`), not `$this->resource->token`, so
        // OpenAPI generators type them from the @property-read tags above.
        return [
            'status' => LoginStatus::ChallengeRequired->value,
            'challenge_token' => $this->token,
            'expires_at' => $this->expiresAt->toIso8601ZuluString(),
            'attempts_left' => $this->attemptsLeft,
            'method' => $this->method->value,
            'completed' => $this->resource->completedSteps(),
            'remaining' => $this->resource->remainingSteps(),
        ];
    }
}
