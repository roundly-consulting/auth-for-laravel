<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Email;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * The signed-in "send me the verification email": the same limits as the guest resend —
 * the per-address `email_request_account` budget (429 once spent) and the per-account
 * `verification.resend_decay` cooldown (inside it nothing is sent, the answer is the
 * same) — so a session cannot mail-bomb its own (or a typo'd) address.
 */
final readonly class RequestEmailVerification
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private SendEmailVerification $send,
    ) {}

    /**
     * @throws TooManyAttempts
     */
    public function execute(string $guard, Account $account, SessionContext $context): void
    {
        $config = $this->guards->owning($guard, $account);

        if ($config->verificationMode() === EmailVerificationMode::Off) {
            throw new LoginMethodDisabled;
        }

        $email = $account->accountEmail();

        if ($email === null || $account->hasVerifiedEmail()) {
            return;
        }

        $this->throttle->attempt($config, [ThrottleKind::EmailRequestAccount], $email, $context);

        if ($this->throttle->cooldown(SendEmailVerification::cooldownKey($guard, $account), $config->verificationResendDecay())) {
            $this->send->execute($guard, $account, $context);
        }
    }
}
