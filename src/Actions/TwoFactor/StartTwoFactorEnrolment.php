<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\TwoFactor;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorSetupData;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\TwoFactorEnrolments;

/**
 * Starts a TOTP enrolment for a signed-in account (the HTTP layer requires a recent
 * re-authentication: an attacker holding a stolen token must not enrol their own
 * authenticator and lock the owner out).
 */
final readonly class StartTwoFactorEnrolment
{
    public function __construct(
        private GuardRegistry $guards,
        private TwoFactorEnrolments $enrolments,
    ) {}

    public function execute(string $guard, Account $account): TwoFactorSetupData
    {
        $config = $this->guards->owning($guard, $account);

        if ($config->twoFactorMode() === TwoFactorMode::Off) {
            throw new LoginMethodDisabled;
        }

        return $this->enrolments->start($config, $account);
    }
}
