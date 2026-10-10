<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\TwoFactor;

use Illuminate\Database\Eloquent\Model;
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
use RoundlyConsulting\Auth\Exceptions\TwoFactorNotEnabled;
use RoundlyConsulting\Auth\Exceptions\TwoFactorRequired;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Actors;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

/**
 * Disables TOTP — refused (409) while the guard requires it, or when the account has
 * none enabled (nothing is written, invalidated or announced). Applies
 * `invalidation.two_factor_changed` and returns the pair re-issued to the caller's
 * `$current` device (none without one — an admin/CLI disable keeps no device).
 *
 * `$actor` is who disabled it when it was not the account (an admin): the owner gets the
 * `by_actor` copy. Another actor together with `$current` is refused before anything is
 * written — that token is the account's own device, never the admin's.
 */
final readonly class DisableTwoFactor
{
    public function __construct(
        private GuardRegistry $guards,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, ?CurrentToken $current = null, ?SessionContext $context = null, ?Model $actor = null): ?TokenPair
    {
        $config = $this->guards->owning($guard, $account);
        $actor = Actors::other($account, $actor, $current);
        $data = new NotificationData($guard, actor: Actors::reference($actor));

        match ($config->twoFactorMode()) {
            TwoFactorMode::Off => throw new LoginMethodDisabled,
            TwoFactorMode::Required => throw new TwoFactorRequired,
            TwoFactorMode::Optional => null,
        };

        $model = AccountModels::twoFactor($account);

        if (! $model->hasTwoFactorEnabled()) {
            throw new TwoFactorNotEnabled;
        }

        TwoFactor::for($model)->disable();

        event(new TwoFactorDisabled($guard, $account, $actor));
        $this->notifications->send($config, NotificationType::TwoFactorDisabled, $account, $data);

        return $this->invalidate->execute($config, $account, InvalidationReason::TwoFactorChanged, $current, $context ?? new SessionContext)->tokens;
    }
}
