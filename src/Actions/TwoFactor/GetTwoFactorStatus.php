<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\TwoFactor;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorStatusData;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;

final readonly class GetTwoFactorStatus
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account): TwoFactorStatusData
    {
        $config = $this->guards->get($guard);
        $model = AccountModels::twoFactor($account);

        return new TwoFactorStatusData(
            enabled: $model->hasTwoFactorEnabled(),
            pending: $model->hasPendingTwoFactor(),
            recoveryCodesRemaining: count($model->twoFactorRecoveryCodes()),
            mode: $config->twoFactorMode(),
        );
    }
}
