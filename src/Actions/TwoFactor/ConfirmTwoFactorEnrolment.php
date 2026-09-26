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
use RoundlyConsulting\Auth\Events\TwoFactorEnabled;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorNotPendingException;
use SensitiveParameter;

/**
 * Confirms a pending TOTP enrolment, then applies `invalidation.two_factor_changed`.
 * Returns the pair re-issued to the calling device under `others` (the default) — the
 * client must swap to it, its current access token dies with the change.
 *
 * Only a PENDING enrolment can be confirmed: with TOTP already on there is nothing to
 * confirm, and the answer is the same `invalid_code` as a wrong code — before any write,
 * invalidation or notification.
 */
final readonly class ConfirmTwoFactorEnrolment
{
    public function __construct(
        private GuardRegistry $guards,
        private ConfirmEnrolment $confirmEnrolment,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, #[SensitiveParameter] string $code, CurrentToken $current, SessionContext $context): ?TokenPair
    {
        $config = $this->guards->get($guard);

        if ($config->twoFactorMode() === TwoFactorMode::Off) {
            throw new LoginMethodDisabled;
        }

        $model = AccountModels::twoFactor($account);

        if ($model->hasTwoFactorEnabled()) {
            throw new InvalidCode;
        }

        try {
            $this->confirmEnrolment->execute($model, $code);
        } catch (InvalidTwoFactorCodeException|TwoFactorNotPendingException $e) {
            throw new InvalidCode($e);
        }

        event(new TwoFactorEnabled($guard, $account));
        $this->notifications->send($config, NotificationType::TwoFactorEnabled, $account, new NotificationData($guard));

        return $this->invalidate->execute($config, $account, InvalidationReason::TwoFactorChanged, $current, $context)->tokens;
    }
}
