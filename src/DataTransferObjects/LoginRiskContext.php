<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\GuardConfig;

final readonly class LoginRiskContext
{
    public function __construct(
        public GuardConfig $guard,
        public Account $account,
        public LoginMethod $method,
        public SessionContext $context,
        public bool $newDevice,
    ) {}
}
