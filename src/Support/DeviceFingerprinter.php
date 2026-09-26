<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Contracts\FingerprintsDevices;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * `HMAC(guard ‖ device id)` when the client sends the device header, else
 * `HMAC(guard ‖ user agent)`; null when neither identifies the device.
 */
final readonly class DeviceFingerprinter implements FingerprintsDevices
{
    public function __construct(private SecretHasher $hasher) {}

    public function fingerprint(SessionContext $context, GuardConfig $guard): ?string
    {
        if ($context->deviceId !== null) {
            return $this->hasher->fingerprint($guard->name(), 'device', $context->deviceId);
        }

        if ($context->userAgent !== null) {
            return $this->hasher->fingerprint($guard->name(), 'ua', $context->userAgent);
        }

        return null;
    }
}
