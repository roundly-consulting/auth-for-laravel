<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Email;

use RoundlyConsulting\Auth\Actions\OneTimeTokens\IssueOneTimeToken;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Events\EmailVerificationSent;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\UrlTemplate;

/**
 * Mails a verification link (or code, per `verification.channel`) to the account's
 * current address. Each send kills the previous one. A no-op for verified accounts.
 */
final readonly class SendEmailVerification
{
    public function __construct(
        private GuardRegistry $guards,
        private IssueOneTimeToken $issue,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, ?SessionContext $context = null): void
    {
        $config = $this->guards->get($guard);

        if ($config->verificationMode() === EmailVerificationMode::Off) {
            throw new LoginMethodDisabled;
        }

        $email = $account->accountEmail();

        if ($email === null || $account->hasVerifiedEmail()) {
            return;
        }

        $secret = $this->issue->execute($config, $account, OneTimeTokenPurpose::EmailVerification, $email, $context ?? new SessionContext);

        $this->notifications->send($config, NotificationType::VerifyEmail, $account, new NotificationData(
            guard: $guard,
            url: $secret->token === null ? null : UrlTemplate::render($config, UrlKind::VerifyEmail, $secret->token, $email),
            code: $secret->code,
            expiresAt: $secret->record->expires_at,
        ));

        event(new EmailVerificationSent($guard, $account));
    }
}
