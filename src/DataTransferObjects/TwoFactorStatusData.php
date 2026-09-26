<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\TwoFactorMode;

final readonly class TwoFactorStatusData
{
    public function __construct(
        public bool $enabled,
        public bool $pending,
        public int $recoveryCodesRemaining,
        public TwoFactorMode $mode,
    ) {}
}
