<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\IssueOneTimeToken;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\EmailOtpRequested;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Sends a short sign-in code to a real, enabled account — and nothing to anyone else.
 * Always 202 at the HTTP layer.
 */
final readonly class RequestEmailOtp
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private IssueOneTimeToken $issue,
        private NotificationDispatcher $notifications,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(string $guard, string $email, SessionContext $context): void
    {
        $config = $this->guards->get($guard);

        if (! $config->loginMethodEnabled(LoginMethod::EmailOtp)) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->attempt($config, [ThrottleKind::EmailRequest, ThrottleKind::EmailRequestIp, ThrottleKind::EmailRequestAccount], $email, $context, ActivityType::EmailOtpRequest);

        $account = (new AccountRepository($config))->findByEmail($email);
        $known = $account !== null && ! $account->isDisabled();

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::EmailOtpRequest,
            outcome: $known ? ActivityOutcome::Succeeded : ActivityOutcome::FailedCredentials,
            context: $context,
            method: LoginMethod::EmailOtp->value,
            account: $account,
            identifier: $email,
        ));

        if (! $known) {
            return;
        }

        $secret = $this->issue->execute($config, $account, OneTimeTokenPurpose::EmailOtp, (string) $account->accountEmail(), $context);

        $this->notifications->send($config, NotificationType::EmailOtp, $account, new NotificationData(
            guard: $guard,
            code: $secret->code,
            expiresAt: $secret->record->expires_at,
        ));

        event(new EmailOtpRequested($guard, $account));
    }
}
