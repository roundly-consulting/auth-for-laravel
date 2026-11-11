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
 * @property-read string $secret
 * @property-read string $provisioningUri
 * @property-read string|null $qrSvg
 * @property-read list<string> $recoveryCodes
 * @property-read string $issuer
 */
class TwoFactorSetupResource extends JsonResource
{
    /** @var string|null */
    public static $wrap = null;

    /**
     * @return array{secret: string, provisioning_uri: string, qr_svg: string|null, recovery_codes: list<string>, issuer: string}
     */
    public function toArray(Request $request): array
    {
        // Read through the resource so OpenAPI generators type the fields from @property-read.
        return [
            'secret' => $this->secret,
            'provisioning_uri' => $this->provisioningUri,
            'qr_svg' => $this->qrSvg,
            'recovery_codes' => $this->recoveryCodes,
            'issuer' => $this->issuer,
        ];
    }
}
