<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Contracts\AssessesLoginRisk;
use RoundlyConsulting\Auth\DataTransferObjects\LoginRiskContext;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;
use RoundlyConsulting\Auth\Enums\RiskLevel;

/**
 * The default assessor: every login is low risk. Bind your own (per guard via
 * `risk.assessor`) to feed impossible-travel, ASN or reputation signals.
 */
final class NullRiskAssessor implements AssessesLoginRisk
{
    public function assess(LoginRiskContext $context): RiskAssessment
    {
        return new RiskAssessment(RiskLevel::Low);
    }
}
