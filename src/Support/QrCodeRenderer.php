<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Contracts\RendersQrCode;
use RoundlyConsulting\Qr\Enums\ErrorCorrection;
use RoundlyConsulting\Qr\Exceptions\QrException;
use RoundlyConsulting\Qr\Facades\Qr;
use SensitiveParameter;

/**
 * The only class that touches qr-for-laravel: renders two-factor's `otpauth://` URI
 * verbatim (qr never caches a secret-sensitivity payload). A QR failure is reported and
 * yields null — the client still gets the URI and the secret, so a QR edge case can
 * never block an enrolment (or a forced-enrolment login).
 */
final class QrCodeRenderer implements RendersQrCode
{
    public function otpauthSvg(#[SensitiveParameter] string $provisioningUri, int $size): ?string
    {
        try {
            return Qr::otpauth($provisioningUri)
                ->size($size)
                ->errorCorrection(ErrorCorrection::Medium)
                ->title($this->title())
                ->svg()
                ->toString();
        } catch (QrException $e) {
            report($e);

            return null;
        }
    }

    private function title(): string
    {
        $title = __('authentication::messages.two_factor.qr_title');

        return is_string($title) ? $title : 'Two-factor authentication';
    }
}
