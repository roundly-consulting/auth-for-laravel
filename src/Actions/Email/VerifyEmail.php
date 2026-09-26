<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Email;

use RoundlyConsulting\Auth\Actions\OneTimeTokens\ConsumeOneTimeToken;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\VerifyOneTimeCode;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Enums\VerificationChannel;
use RoundlyConsulting\Auth\Events\EmailVerified;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;
use SensitiveParameter;

/**
 * Verifies an address with its link token or its code (+ address). The secret must
 * have been sent to the account's CURRENT address — a link sent before an email change
 * cannot verify the new one. Issues no tokens: the `email_verified` claim follows at the
 * next refresh.
 */
final readonly class VerifyEmail
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private ConsumeOneTimeToken $consume,
        private VerifyOneTimeCode $verifyCode,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $tokenOrCode, ?string $email, SessionContext $context): Account
    {
        $config = $this->guards->get($guard);

        if ($config->verificationMode() === EmailVerificationMode::Off) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->attempt($config, [ThrottleKind::Verification], $email, $context);

        $usesCode = $config->verificationChannel() === VerificationChannel::Code;

        if ($usesCode && $email === null) {
            throw new InvalidCode;
        }

        $account = $usesCode
            ? $this->verifyCode->execute($guard, OneTimeTokenPurpose::EmailVerification, (string) $email, $tokenOrCode)->account
            : $this->consume->execute($guard, OneTimeTokenPurpose::EmailVerification, $tokenOrCode, $context)->account;

        if (! $account->hasVerifiedEmail()) {
            $account->markEmailAsVerified();
        }

        event(new EmailVerified($guard, $account));

        return $account;
    }
}
