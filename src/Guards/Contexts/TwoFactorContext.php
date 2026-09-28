<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Auth\Actions\TwoFactor\ConfirmTwoFactorEnrolment;
use RoundlyConsulting\Auth\Actions\TwoFactor\DisableTwoFactor;
use RoundlyConsulting\Auth\Actions\TwoFactor\GetTwoFactorStatus;
use RoundlyConsulting\Auth\Actions\TwoFactor\RegenerateRecoveryCodes;
use RoundlyConsulting\Auth\Actions\TwoFactor\StartTwoFactorEnrolment;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\RecoveryCodesData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorSetupData;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorStatusData;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

/**
 * An account's TOTP on one guard — `Authentication::twoFactor()` /
 * `Authentication::guard('clients')->twoFactor()`. Every method refuses another guard's
 * account before it writes, and applies the guard's two-factor mode and
 * `invalidation.two_factor_changed` exactly like the HTTP endpoints.
 *
 * Pass the caller's `$current` token (and `$context`) when acting for the signed-in
 * account: its device is kept under `others` and the re-issued pair is returned. Leave
 * them out for admin/CLI calls. The HTTP layer also demands a recent re-authentication
 * for start/disable/regenerate — host code acting for the user vouches for it, or calls
 * `reauthentication()->ensureFor()` first.
 */
final readonly class TwoFactorContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * Enabled / pending / recovery codes left, and the guard's mode.
     */
    public function status(Account $account): TwoFactorStatusData
    {
        $this->own($account);

        return $this->make(GetTwoFactorStatus::class)->execute($this->guardName(), $account);
    }

    /**
     * Start (or restart) a pending enrolment: secret, `otpauth://` URI, QR SVG and the
     * recovery codes, shown once.
     */
    public function start(Account $account): TwoFactorSetupData
    {
        $this->own($account);

        return $this->make(StartTwoFactorEnrolment::class)->execute($this->guardName(), $account);
    }

    /**
     * Confirm the pending enrolment with its first code; returns the pair re-issued to
     * `$current`'s device under `others`.
     */
    public function confirm(Account $account, #[SensitiveParameter] string $code, ?CurrentToken $current = null, ?SessionContext $context = null): ?TokenPair
    {
        $this->own($account);

        return $this->make(ConfirmTwoFactorEnrolment::class)->execute($this->guardName(), $account, $code, $current, $context);
    }

    /**
     * Turn TOTP off (refused while the guard requires it).
     */
    public function disable(Account $account, ?CurrentToken $current = null, ?SessionContext $context = null): ?TokenPair
    {
        $this->own($account);

        return $this->make(DisableTwoFactor::class)->execute($this->guardName(), $account, $current, $context);
    }

    /**
     * Replace the recovery codes; the plaintext set is returned once.
     */
    public function regenerateRecoveryCodes(Account $account, ?CurrentToken $current = null, ?SessionContext $context = null): RecoveryCodesData
    {
        $this->own($account);

        return $this->make(RegenerateRecoveryCodes::class)->execute($this->guardName(), $account, $current, $context);
    }
}
