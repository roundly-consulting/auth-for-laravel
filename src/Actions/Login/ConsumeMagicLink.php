<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\ConsumeOneTimeToken;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;
use SensitiveParameter;

/**
 * Signs in with a magic link (amr `email`). With `verification.verify_on_email_login`
 * the address counts as verified.
 */
final readonly class ConsumeMagicLink
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private ConsumeOneTimeToken $consume,
        private CompleteFirstFactor $completeFirstFactor,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $token, SessionContext $context): LoginResult
    {
        $config = $this->guards->get($guard);

        if (! $config->loginMethodEnabled(LoginMethod::MagicLink)) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->ensure($config, [ThrottleKind::LoginIp], null, $context, ActivityType::MagicLinkLogin);

        try {
            $redeemed = $this->consume->execute($guard, OneTimeTokenPurpose::MagicLink, $token, $context);
        } catch (InvalidOneTimeToken $e) {
            $this->throttle->hit($config, [ThrottleKind::LoginIp], null, $context->ipAddress);
            $this->recordActivity->execute(new LoginActivityData(
                guard: $guard,
                type: ActivityType::MagicLinkLogin,
                outcome: ActivityOutcome::FailedToken,
                context: $context,
                method: LoginMethod::MagicLink->value,
            ));

            throw $e;
        }

        return $this->completeFirstFactor->execute($config, $redeemed->account, LoginMethod::MagicLink, $context, [AuthMethodReference::Email]);
    }
}
