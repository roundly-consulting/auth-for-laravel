<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Illuminate\Contracts\Container\Container;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\Passwords\ChangePassword;
use RoundlyConsulting\Auth\Actions\Passwords\RequestPasswordReset;
use RoundlyConsulting\Auth\Actions\Passwords\ResetPassword;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\Actions\Passwords\ValidatePasswordPolicy;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordResetData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Rules\PasswordPolicy;
use SensitiveParameter;

/**
 * Passwords on one guard — `Authentication::passwords()` /
 * `Authentication::guard('clients')->passwords()`: the admin set, the signed-in change,
 * the emailed reset, and the guard's policy as a check or a validation rule. Every
 * account-taking method refuses another guard's account before it writes.
 */
final readonly class PasswordsContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * Set a password from host code (an admin, a support tool): the policy, the
     * invalidation of `$reason` (no device kept — the caller is not the account) and the
     * owner's notification.
     */
    public function set(Account $account, #[SensitiveParameter] string $password, InvalidationReason $reason = InvalidationReason::PasswordReset): void
    {
        $this->own($account);

        $this->make(SetPassword::class)->execute($this->guardName(), $account, $password, $reason);
    }

    /**
     * The signed-in change: the current password (throttled), or — for an account without
     * one — a recent re-authentication; returns the pair re-issued to the caller.
     */
    public function change(Account $account, ChangePasswordData $data): ?TokenPair
    {
        $this->own($account);

        return $this->make(ChangePassword::class)->execute($this->guardName(), $account, $data);
    }

    /**
     * "Forgot password": mails a reset link to a real, enabled account only.
     */
    public function requestReset(string $email, SessionContext $context): void
    {
        $this->make(RequestPasswordReset::class)->execute($this->guardName(), $email, $context);
    }

    /**
     * Reset through the emailed link; signs in when `passwords.reset.login_after`.
     */
    public function reset(PasswordResetData $data): ?LoginResult
    {
        return $this->make(ResetPassword::class)->execute($this->guardName(), $data);
    }

    /**
     * Check a password against the guard's policy.
     *
     * @throws ValidationException on `password`
     */
    public function validate(#[SensitiveParameter] string $password, ?Account $account = null, ?string $email = null): void
    {
        if ($account !== null) {
            $this->own($account);
        }

        $this->make(ValidatePasswordPolicy::class)->execute($this->config, $password, $account, $email);
    }

    /**
     * The guard's policy as a validation rule for the host's own forms.
     */
    public function rule(?string $email = null): PasswordPolicy
    {
        return new PasswordPolicy($this->config, $email);
    }
}
