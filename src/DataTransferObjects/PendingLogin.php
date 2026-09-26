<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\RiskLevel;

/**
 * Everything the success tail of a login needs, whether it runs straight after the
 * first factor or when a challenge finalizes.
 */
final readonly class PendingLogin
{
    /**
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function __construct(
        public string $guard,
        public Account $account,
        public LoginMethod $method,
        public array $authMethods,
        public CarbonImmutable $authTime,
        public SessionContext $context,
        public bool $newDevice = false,
        public RiskLevel $riskLevel = RiskLevel::Low,
        public bool $notifyRisk = false,
        public ?int $challengeId = null,
        public ?string $identifier = null,
    ) {}
}
