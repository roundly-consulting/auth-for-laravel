<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\TwoFactor;

use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Events\TwoFactorDisabled;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\TwoFactorRequired;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\TwoFactor\Actions\DisableTwoFactor as DisableTwoFactorAction;

/**
 * Disables TOTP — refused (409) while the guard requires it. Applies
 * `invalidation.two_factor_changed` and returns the pair re-issued to the caller.
 */
final readonly class DisableTwoFactor
{
    public function __construct(
        private GuardRegistry $guards,
        private DisableTwoFactorAction $disable,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, CurrentToken $current, SessionContext $context): ?TokenPair
    {
        $config = $this->guards->get($guard);

        match ($config->twoFactorMode()) {
            TwoFactorMode::Off => throw new LoginMethodDisabled,
            TwoFactorMode::Required => throw new TwoFactorRequired,
            TwoFactorMode::Optional => null,
        };

        $this->disable->execute(AccountModels::twoFactor($account));

        event(new TwoFactorDisabled($guard, $account));
        $this->notifications->send($config, NotificationType::TwoFactorDisabled, $account, new NotificationData($guard));

        return $this->invalidate->execute($config, $account, InvalidationReason::TwoFactorChanged, $current, $context)->tokens;
    }
}
