<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorSetupData;

/**
 * A TOTP enrolment, shown once. Not final: a documented extension point.
 *
 * @property TwoFactorSetupData $resource
 */
class TwoFactorSetupResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $setup = $this->resource;

        return [
            'secret' => $setup->secret,
            'provisioning_uri' => $setup->provisioningUri,
            'qr_svg' => $setup->qrSvg,
            'recovery_codes' => $setup->recoveryCodes,
            'issuer' => $setup->issuer,
        ];
    }
}
