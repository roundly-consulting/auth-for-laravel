<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use RoundlyConsulting\Auth\Actions\OneTimeTokens\IssueOneTimeToken;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\FactorNotAllowed;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Mails a re-authentication code to the account's current address — only for accounts
 * that may re-authenticate by email (no password, no second factor).
 */
final readonly class SendReauthenticationCode
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private IssueOneTimeToken $issue,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, SessionContext $context): void
    {
        $config = $this->guards->get($guard);

        if (! in_array(ReauthenticationMethod::EmailOtp, ReauthenticationMethods::available($config, $account), true)) {
            throw new FactorNotAllowed;
        }

        $email = (string) $account->accountEmail();

        $this->throttle->attempt($config, [ThrottleKind::EmailRequestAccount], $email, $context, ActivityType::Reauthentication);

        $secret = $this->issue->execute($config, $account, OneTimeTokenPurpose::Reauthentication, $email, $context);

        $this->notifications->send($config, NotificationType::EmailOtp, $account, new NotificationData(
            guard: $guard,
            code: $secret->code,
            expiresAt: $secret->record->expires_at,
        ));
    }
}
