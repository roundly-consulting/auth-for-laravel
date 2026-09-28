<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\TwoFactor;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorStatusData;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

final readonly class GetTwoFactorStatus
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account): TwoFactorStatusData
    {
        $config = $this->guards->owning($guard, $account);
        $status = TwoFactor::for(AccountModels::twoFactor($account))->status();

        return new TwoFactorStatusData(
            enabled: $status->enabled,
            pending: $status->pending,
            recoveryCodesRemaining: $status->recoveryCodesRemaining,
            mode: $config->twoFactorMode(),
        );
    }
}
