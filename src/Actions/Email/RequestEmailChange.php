<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Email;

use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\IssueOneTimeToken;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\EmailChangeData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Events\EmailChangeRequested;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Auth\Support\UrlTemplate;

/**
 * Starts an email change: nothing changes until the NEW address confirms, and the old
 * address is told. An address already in use gets an "account exists" notice instead —
 * at most one per address per cooldown, shared with registration and invitations — with
 * the same answer to the caller and the same old-address notice, so an email change
 * cannot probe for accounts.
 */
final readonly class RequestEmailChange
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private IssueOneTimeToken $issue,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, EmailChangeData $data): void
    {
        $config = $this->guards->owning($guard, $account);

        if (! $config->emailChangeEnabled()) {
            throw new LoginMethodDisabled;
        }

        $accounts = new AccountRepository($config);
        $new = $accounts->normalizeEmail($data->newEmail);
        $old = (string) $account->accountEmail();

        Validator::make(['email' => $new], ['email' => ['required', 'email', 'max:255']])->validate();

        if ($new === $accounts->normalizeEmail($old)) {
            throw ValidationException::withMessages(['email' => __('authentication::validation.email_unchanged')]);
        }

        $this->throttle->attempt($config, [ThrottleKind::EmailRequestAccount], $old, $data->context);

        if ($accounts->emailTaken($new)) {
            // Shared with registration and invitations: no path mails an address more often.
            if ($this->throttle->accountExistsCooldown($config, $new)) {
                $this->notifications->sendTo($config, NotificationType::AccountExists, $new, new NotificationData($guard), $account->preferredLocale());
            }

            $this->notifyOldAddress($config, $guard, $account, $old, $new);

            return;
        }

        $secret = $this->issue->execute($config, $account, OneTimeTokenPurpose::EmailChange, $new, $data->context, ['old_email' => $old]);

        $this->notifications->sendTo($config, NotificationType::EmailChangeConfirmation, $new, new NotificationData(
            guard: $guard,
            url: UrlTemplate::render($config, UrlKind::ConfirmEmailChange, (string) $secret->token, $new),
            expiresAt: $secret->record->expires_at,
        ), $account->preferredLocale());

        $this->notifyOldAddress($config, $guard, $account, $old, $new);

        // Server-side only: it fires for an issued link, so surfacing it would reveal a taken address.
        event(new EmailChangeRequested($guard, $account, $new));
    }

    /**
     * The old mailbox hears about every request, taken address or not — the requester
     * reads it, so a notice for a free address only would answer the probe.
     */
    private function notifyOldAddress(GuardConfig $config, string $guard, Account $account, string $old, string $new): void
    {
        if ($config->emailChangeNotifiesOldAddress()) {
            $this->notifications->sendTo($config, NotificationType::EmailChangeRequested, $old, new NotificationData(
                guard: $guard,
                replacements: ['new_email' => $new],
            ), $account->preferredLocale());
        }
    }
}
