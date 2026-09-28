<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passwords;

use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\PasswordWriter;
use SensitiveParameter;

/**
 * Sets a password from host code (an admin, a support tool): policy, hash, the
 * invalidation of the given reason (no kept device — the caller is not the account),
 * the owner's notification.
 */
final readonly class SetPassword
{
    public function __construct(
        private GuardRegistry $guards,
        private ValidatePasswordPolicy $policy,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, #[SensitiveParameter] string $password, InvalidationReason $reason = InvalidationReason::PasswordReset): void
    {
        $config = $this->guards->owning($guard, $account);

        $this->policy->execute($config, $password, $account);

        PasswordWriter::write($account, $password);

        $this->invalidate->execute($config, $account, $reason, null, new SessionContext);

        event(new PasswordChanged($guard, $account));
        $this->notifications->send($config, NotificationType::PasswordChanged, $account, new NotificationData($guard));
    }
}
