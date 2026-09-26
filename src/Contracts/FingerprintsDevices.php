<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Guards\GuardConfig;

interface FingerprintsDevices
{
    /**
     * A 64-hex keyed fingerprint of the device, or null when nothing identifies it.
     */
    public function fingerprint(SessionContext $context, GuardConfig $guard): ?string;
}
