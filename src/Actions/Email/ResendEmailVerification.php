<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Email;

use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * A guest "resend the verification email": throttled per address+IP, IP and address,
 * plus a per-account `verification.resend_decay` cooldown. Sends only to a real,
 * unverified account; always 202 at the HTTP layer.
 */
final readonly class ResendEmailVerification
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private SendEmailVerification $send,
    ) {}

    public function execute(string $guard, string $email, SessionContext $context): void
    {
        $config = $this->guards->get($guard);

        if ($config->verificationMode() === EmailVerificationMode::Off) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->attempt($config, [ThrottleKind::EmailRequest, ThrottleKind::EmailRequestIp, ThrottleKind::EmailRequestAccount], $email, $context);

        $account = (new AccountRepository($config))->findByEmail($email);

        if ($account === null || $account->hasVerifiedEmail() || $account->isDisabled()) {
            return;
        }

        $model = AccountModels::of($account);

        if ($this->throttle->cooldown("authentication:{$guard}:verification-resend:{$model->getMorphClass()}:{$model->getKey()}", $config->verificationResendDecay())) {
            $this->send->execute($guard, $account, $context);
        }
    }
}
