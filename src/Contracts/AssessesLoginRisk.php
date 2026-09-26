<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use RoundlyConsulting\Auth\DataTransferObjects\LoginRiskContext;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;

/**
 * Per-guard `risk.assessor`: rates a login after its first factor verified.
 */
interface AssessesLoginRisk
{
    public function assess(LoginRiskContext $context): RiskAssessment;
}
