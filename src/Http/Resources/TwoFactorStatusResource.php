<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorStatusData;

/**
 * Not final: a documented extension point.
 *
 * @property TwoFactorStatusData $resource
 */
class TwoFactorStatusResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'enabled' => $this->resource->enabled,
            'pending' => $this->resource->pending,
            'recovery_codes_remaining' => $this->resource->recoveryCodesRemaining,
            'mode' => $this->resource->mode->value,
        ];
    }
}
