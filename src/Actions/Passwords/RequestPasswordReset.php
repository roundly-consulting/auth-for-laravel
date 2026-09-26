<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passwords;

use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\IssueOneTimeToken;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Events\PasswordResetRequested;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Auth\Support\UrlTemplate;

/**
 * "Forgot password": mails a reset link to a real, enabled account and nothing to
 * anyone else. Always 202 at the HTTP layer — the unknown-address case is not revealed.
 */
final readonly class RequestPasswordReset
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

        if (! $config->passwordResetEnabled()) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->attempt($config, [ThrottleKind::EmailRequest, ThrottleKind::EmailRequestIp, ThrottleKind::EmailRequestAccount], $email, $context, ActivityType::PasswordResetRequest);

        $account = (new AccountRepository($config))->findByEmail($email);
        $known = $account !== null && ! $account->isDisabled();

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::PasswordResetRequest,
            outcome: $known ? ActivityOutcome::Succeeded : ActivityOutcome::FailedCredentials,
            context: $context,
            account: $account,
            identifier: $email,
        ));

        if (! $known) {
            return;
        }

        $address = (string) $account->accountEmail();
        $secret = $this->issue->execute($config, $account, OneTimeTokenPurpose::PasswordReset, $address, $context);

        $this->notifications->send($config, NotificationType::ResetPassword, $account, new NotificationData(
            guard: $guard,
            url: UrlTemplate::render($config, UrlKind::ResetPassword, (string) $secret->token, $address),
            expiresAt: $secret->record->expires_at,
        ));

        event(new PasswordResetRequested($guard, $account));
    }
}
