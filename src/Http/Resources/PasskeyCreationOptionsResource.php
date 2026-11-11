<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;

/**
 * The registration options a passkey registration or enrolment step hands to
 * `navigator.credentials.create({ publicKey })`. Same body as {@see PasskeyOptionsResource};
 * the narrower wrapped type lets OpenAPI generators name and type it. Not final: a
 * documented extension point.
 *
 * @property CreationOptionsData $resource
 */
class PasskeyCreationOptionsResource extends PasskeyOptionsResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return $this->resource->jsonSerialize();
    }
}
