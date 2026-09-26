<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\VerifyOneTimeCode;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;
use SensitiveParameter;

/**
 * Signs in with an emailed code (amr `otp`). A code guess IS a login attempt: it runs
 * through the three login buckets, and never reveals attempts left (that would tell a
 * real address from an unknown one).
 */
final readonly class VerifyEmailOtp
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private VerifyOneTimeCode $verify,
        private CompleteFirstFactor $completeFirstFactor,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(string $guard, string $email, #[SensitiveParameter] string $code, SessionContext $context): LoginResult
    {
        $config = $this->guards->get($guard);

        if (! $config->loginMethodEnabled(LoginMethod::EmailOtp)) {
            throw new LoginMethodDisabled;
        }

        $kinds = [ThrottleKind::Login, ThrottleKind::LoginIp, ThrottleKind::LoginAccount];
        $this->throttle->attempt($config, $kinds, $email, $context, ActivityType::EmailOtpLogin);

        try {
            $redeemed = $this->verify->execute($guard, OneTimeTokenPurpose::EmailOtp, $email, $code);
        } catch (InvalidCode $e) {
            $this->recordActivity->execute(new LoginActivityData(
                guard: $guard,
                type: ActivityType::EmailOtpLogin,
                outcome: ActivityOutcome::FailedToken,
                context: $context,
                method: LoginMethod::EmailOtp->value,
                identifier: $email,
            ));

            throw $e;
        }

        $this->throttle->release($config, $kinds, $email, $context->ipAddress);

        return $this->completeFirstFactor->execute($config, $redeemed->account, LoginMethod::EmailOtp, $context, [AuthMethodReference::Otp]);
    }
}
