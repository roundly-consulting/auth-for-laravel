<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\TwoFactor;

use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\RecoveryCodesData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Events\RecoveryCodesRegenerated;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\TwoFactorNotEnabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\TwoFactor\Actions\RegenerateRecoveryCodes as RegenerateRecoveryCodesAction;

/**
 * Replaces the recovery codes (plaintext returned once), applies
 * `invalidation.two_factor_changed`, and returns the pair re-issued to the caller.
 * Refused (409) for an account without TOTP — before any write or invalidation.
 */
final readonly class RegenerateRecoveryCodes
{
    public function __construct(
        private GuardRegistry $guards,
        private RegenerateRecoveryCodesAction $regenerate,
        private InvalidateAccountTokens $invalidate,
    ) {}

    public function execute(string $guard, Account $account, CurrentToken $current, SessionContext $context): RecoveryCodesData
    {
        $config = $this->guards->get($guard);

        if ($config->twoFactorMode() === TwoFactorMode::Off) {
            throw new LoginMethodDisabled;
        }

        $model = AccountModels::twoFactor($account);

        if (! $model->hasTwoFactorEnabled()) {
            throw new TwoFactorNotEnabled;
        }

        $codes = $this->regenerate->execute($model);

        event(new RecoveryCodesRegenerated($guard, $account));

        return new RecoveryCodesData($codes, $this->invalidate->execute($config, $account, InvalidationReason::TwoFactorChanged, $current, $context)->tokens);
    }
}
