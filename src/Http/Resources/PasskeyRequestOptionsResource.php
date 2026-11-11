<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;

/**
 * The assertion options a passkey login, challenge step or re-authentication hands to
 * `navigator.credentials.get({ publicKey })`. Same body as {@see PasskeyOptionsResource};
 * the narrower wrapped type lets OpenAPI generators name and type it. Not final: a
 * documented extension point.
 *
 * @property RequestOptionsData $resource
 */
class PasskeyRequestOptionsResource extends PasskeyOptionsResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return $this->resource->jsonSerialize();
    }
}
