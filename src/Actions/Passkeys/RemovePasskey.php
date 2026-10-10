<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passkeys;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\PasskeySecondFactor;
use RoundlyConsulting\Auth\Events\PasskeyRemoved;
use RoundlyConsulting\Auth\Exceptions\LastCredential;
use RoundlyConsulting\Auth\Exceptions\PasskeyNotFound;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Actors;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Removes one of the account's passkeys — unless it is the last one and the account
 * would be left without a way in, or the guard requires a passkey (409
 * `last_credential`). The check and the revoke run under the account row lock, so of
 * two concurrent removes the second sees the first. `invalidation.passkey_changed`
 * defaults to `none`: removing a lost key should not log out the device doing it.
 *
 * `$actor` is who removed it when it was not the account (an admin): the owner gets the
 * `by_actor` copy. Another actor together with `$current` is refused before anything is
 * written — that token is the account's own device, never the admin's.
 */
final readonly class RemovePasskey
{
    public function __construct(
        private GuardRegistry $guards,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, int $passkeyId, ?CurrentToken $current = null, ?SessionContext $context = null, ?Model $actor = null): ?TokenPair
    {
        $config = $this->guards->owning($guard, $account);
        $model = AccountModels::passkeys($account);
        $actor = Actors::other($account, $actor, $current);
        $data = new NotificationData($guard, actor: Actors::reference($actor));

        // Count and revoke under the account row lock: the passkeys are separate rows, so
        // only the shared parent serialises two removes — otherwise both pass the count
        // and the account is left without its last way in.
        $model->getConnection()->transaction(function () use ($config, $account, $model, $passkeyId): void {
            $model->newQueryWithoutScopes()->whereKey($model->getKey())->lockForUpdate()->value($model->getKeyName());

            $passkey = $model->passkeys()->whereKey($passkeyId)->first();

            if (! $passkey instanceof Passkey) {
                throw new PasskeyNotFound;
            }

            if ($model->passkeys()->count() <= 1 && $this->lastOneIsNeeded($config, $account)) {
                throw new LastCredential;
            }

            Passkeys::for($model)->revoke($passkey);
        });

        event(new PasskeyRemoved($guard, $account, $passkeyId, $actor));
        $this->notifications->send($config, NotificationType::PasskeyRemoved, $account, $data);

        return $this->invalidate->execute($config, $account, InvalidationReason::PasskeyChanged, $current, $context ?? new SessionContext)->tokens;
    }

    private function lastOneIsNeeded(GuardConfig $guard, Account $account): bool
    {
        $otherWayIn = ($guard->loginMethodEnabled(LoginMethod::Password) && $account->hasPassword())
            || $guard->loginMethodEnabled(LoginMethod::MagicLink)
            || $guard->loginMethodEnabled(LoginMethod::EmailOtp);

        return ! $otherWayIn
            || $guard->passkeyMode() === PasskeyMode::Required
            || $guard->passkeySecondFactor() === PasskeySecondFactor::Required;
    }
}
