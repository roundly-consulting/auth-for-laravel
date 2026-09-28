<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Activity;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Auth\Contracts\AssessesLoginRisk;
use RoundlyConsulting\Auth\DataTransferObjects\LoginRiskContext;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;

/**
 * Runs the guard's `risk.assessor` (or the bound {@see AssessesLoginRisk}, low by default).
 *
 * @internal a login-pipeline step (`CompleteFirstFactor`); swap the assessor through `risk.assessor` / `AssessesLoginRisk`.
 */
final readonly class AssessLoginRisk
{
    public function __construct(private Container $container) {}

    public function execute(LoginRiskContext $context): RiskAssessment
    {
        $class = $context->guard->riskAssessor();
        $assessor = $class === null ? null : $this->container->make($class);

        if (! $assessor instanceof AssessesLoginRisk) {
            $assessor = $this->container->make(AssessesLoginRisk::class);
        }

        return $assessor->assess($context);
    }
}
