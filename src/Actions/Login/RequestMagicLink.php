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
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Events\MagicLinkRequested;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Auth\Support\UrlTemplate;

/**
 * Sends a sign-in link to a real, enabled account — and silently nothing to anyone
 * else. The caller always answers 202 `{status: "sent"}`; delivery happens after the
 * response, so neither the body nor the timing tells the two apart.
 */
final readonly class RequestMagicLink
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

        if (! $config->loginMethodEnabled(LoginMethod::MagicLink)) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->attempt($config, [ThrottleKind::EmailRequest, ThrottleKind::EmailRequestIp, ThrottleKind::EmailRequestAccount], $email, $context, ActivityType::MagicLinkRequest);

        $account = (new AccountRepository($config))->findByEmail($email);
        $known = $account !== null && ! $account->isDisabled();

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::MagicLinkRequest,
            outcome: $known ? ActivityOutcome::Succeeded : ActivityOutcome::FailedCredentials,
            context: $context,
            method: LoginMethod::MagicLink->value,
            account: $account,
            identifier: $email,
        ));

        if (! $known) {
            return;
        }

        $address = (string) $account->accountEmail();
        $secret = $this->issue->execute($config, $account, OneTimeTokenPurpose::MagicLink, $address, $context);

        $this->notifications->send($config, NotificationType::MagicLink, $account, new NotificationData(
            guard: $guard,
            url: UrlTemplate::render($config, UrlKind::MagicLink, (string) $secret->token, $address),
            expiresAt: $secret->record->expires_at,
        ));

        event(new MagicLinkRequested($guard, $account));
    }
}
