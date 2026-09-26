<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

/**
 * A TOTP enrolment to show the user once: the secret (manual entry), the otpauth://
 * URI built by two-factor-for-laravel, its QR SVG (null when disabled or the render
 * failed — never blocks enrolment) and the recovery codes.
 */
final readonly class TwoFactorSetupData
{
    /**
     * @param  list<string>  $recoveryCodes
     */
    public function __construct(
        #[SensitiveParameter] public string $secret,
        #[SensitiveParameter] public string $provisioningUri,
        #[SensitiveParameter] public ?string $qrSvg,
        #[SensitiveParameter] public array $recoveryCodes,
        public string $issuer,
    ) {}
}
