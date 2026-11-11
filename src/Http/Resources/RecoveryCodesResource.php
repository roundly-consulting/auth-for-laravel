<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\RecoveryCodesData;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;

/**
 * Regenerated recovery codes, shown once, plus the re-issued pair (or null): when non-null
 * the client MUST swap to it. Not final: a documented extension point.
 *
 * @property RecoveryCodesData $resource
 * @property-read list<string> $codes
 * @property-read TokenPair|null $tokens
 */
class RecoveryCodesResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array{recovery_codes: list<string>, tokens: TokenPairResource|null}
     */
    public function toArray(Request $request): array
    {
        // Read through the resource so OpenAPI generators type the fields from @property-read.
        return [
            'recovery_codes' => $this->codes,
            'tokens' => $this->tokens === null ? null : new TokenPairResource($this->tokens),
        ];
    }
}
