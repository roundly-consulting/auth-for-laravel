<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\RendersQrCode;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorSetupData;
use RoundlyConsulting\Auth\Exceptions\TwoFactorAlreadyEnabled;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAlreadyEnabledException;

/**
 * Starts (or restarts) a TOTP enrolment through two-factor-for-laravel with the
 * guard's issuer, and adds the QR code. The `otpauth://` URI is two-factor's, verbatim —
 * there is exactly one URI builder in the stack.
 */
final readonly class TwoFactorEnrolments
{
    public function __construct(
        private StartEnrolment $startEnrolment,
        private RendersQrCode $qr,
    ) {}

    /**
     * @throws TwoFactorAlreadyEnabled
     */
    public function start(GuardConfig $guard, Account $account): TwoFactorSetupData
    {
        try {
            $setup = $this->startEnrolment->execute(AccountModels::twoFactor($account), null, $guard->twoFactorIssuer());
        } catch (TwoFactorAlreadyEnabledException $e) {
            throw new TwoFactorAlreadyEnabled($e);
        }

        return new TwoFactorSetupData(
            secret: $setup->secret,
            provisioningUri: $setup->provisioningUri,
            qrSvg: $guard->rendersQrCode() ? $this->qr->otpauthSvg($setup->provisioningUri, $guard->qrSize()) : null,
            recoveryCodes: $setup->recoveryCodes,
            issuer: $setup->issuer,
        );
    }
}
