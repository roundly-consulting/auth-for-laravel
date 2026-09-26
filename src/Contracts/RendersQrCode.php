<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use SensitiveParameter;

/**
 * Renders the TOTP setup QR code. Returns null when rendering failed — enrolment then
 * falls back to the provisioning URI and the secret.
 */
interface RendersQrCode
{
    public function otpauthSvg(#[SensitiveParameter] string $provisioningUri, int $size): ?string;
}
