<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Support;

use RoundlyConsulting\Auth\Contracts\AssessesLoginRisk;
use RoundlyConsulting\Auth\DataTransferObjects\LoginRiskContext;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;
use RoundlyConsulting\Auth\Enums\RiskLevel;

/**
 * Rates every login high, so the guard's `risk.reactions.high` decides it.
 */
final class HighRiskAssessor implements AssessesLoginRisk
{
    public function assess(LoginRiskContext $context): RiskAssessment
    {
        return new RiskAssessment(RiskLevel::High, ['test']);
    }
}
