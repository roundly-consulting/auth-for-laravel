<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\RiskLevel;

final readonly class RiskAssessment
{
    /**
     * @param  list<string>  $signals
     */
    public function __construct(
        public RiskLevel $level = RiskLevel::Low,
        public array $signals = [],
    ) {}
}
