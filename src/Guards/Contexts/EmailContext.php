<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Auth\Actions\Email\ConfirmEmailChange;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailChange;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailVerification;
use RoundlyConsulting\Auth\Actions\Email\ResendEmailVerification;
use RoundlyConsulting\Auth\Actions\Email\SendEmailVerification;
use RoundlyConsulting\Auth\Actions\Email\VerifyEmail;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\EmailChangeData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

/**
 * Email verification and email changes on one guard — `Authentication::email()` /
 * `Authentication::guard('clients')->email()`. Every account-taking method refuses
 * another guard's account before it sends or writes anything.
 *
 * The HTTP layer demands a recent re-authentication before an email change (unless
 * `email_change.require_reauthentication = false`) — host code acting for the user
 * vouches for it, or calls `reauthentication()->ensureFor(SensitiveAction::ChangeEmail, …)`.
 */
final readonly class EmailContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * Mail a verification link or code now — unthrottled, for host code (an admin
     * "resend" button). A no-op for a verified account.
     */
    public function sendVerification(Account $account, ?SessionContext $context = null): void
    {
        $this->own($account);

        $this->make(SendEmailVerification::class)->execute($this->guardName(), $account, $context);
    }

    /**
     * The signed-in "send me the verification email": the per-address budget and the
     * `verification.resend_decay` cooldown apply.
     */
    public function requestVerification(Account $account, SessionContext $context): void
    {
        $this->own($account);

        $this->make(RequestEmailVerification::class)->execute($this->guardName(), $account, $context);
    }

    /**
     * The guest "resend the verification email" — sends only to a real, unverified
     * account and never reveals which.
     */
    public function resendVerification(string $email, SessionContext $context): void
    {
        $this->make(ResendEmailVerification::class)->execute($this->guardName(), $email, $context);
    }

    /**
     * Verify with the link token, or with the code + address (`verification.channel`).
     */
    public function verify(#[SensitiveParameter] string $tokenOrCode, ?string $email, SessionContext $context): Account
    {
        return $this->make(VerifyEmail::class)->execute($this->guardName(), $tokenOrCode, $email, $context);
    }

    /**
     * Start an email change: nothing changes until the new address confirms.
     */
    public function requestChange(Account $account, EmailChangeData $data): void
    {
        $this->own($account);

        $this->make(RequestEmailChange::class)->execute($this->guardName(), $account, $data);
    }

    /**
     * Confirm an email change with the link mailed to the new address.
     */
    public function confirmChange(#[SensitiveParameter] string $token, SessionContext $context): Account
    {
        return $this->make(ConfirmEmailChange::class)->execute($this->guardName(), $token, $context);
    }
}
