<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorStatusData;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;

/**
 * Not final: a documented extension point.
 *
 * @property TwoFactorStatusData $resource
 * @property-read bool $enabled
 * @property-read bool $pending
 * @property-read int $recoveryCodesRemaining
 * @property-read TwoFactorMode $mode
 */
class TwoFactorStatusResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array{enabled: bool, pending: bool, recovery_codes_remaining: int, mode: value-of<TwoFactorMode>}
     */
    public function toArray(Request $request): array
    {
        // Read through the resource so OpenAPI generators type the fields from @property-read.
        return [
            'enabled' => $this->enabled,
            'pending' => $this->pending,
            'recovery_codes_remaining' => $this->recoveryCodesRemaining,
            'mode' => $this->mode->value,
        ];
    }
}
