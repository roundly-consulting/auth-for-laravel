<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;

/**
 * A risk assessment flagged (or denied) a login.
 */
final readonly class SuspiciousLoginDetected
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public RiskAssessment $assessment,
        public SessionContext $context,
    ) {}
}
