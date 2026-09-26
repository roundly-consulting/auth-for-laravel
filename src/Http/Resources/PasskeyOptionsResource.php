<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;

/**
 * WebAuthn options exactly as `navigator.credentials.get/create({ publicKey })` expects,
 * plus the `ceremonyId` the client echoes back. Not final: a documented extension point.
 *
 * @property RequestOptionsData|CreationOptionsData $resource
 */
class PasskeyOptionsResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return $this->resource->jsonSerialize();
    }
}
