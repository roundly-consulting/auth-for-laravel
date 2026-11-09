<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Events\AccountClaimed;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

/**
 * `verification.secure_on_email_login`: an email login (magic link, email code) that
 * verifies an unverified address proved the mailbox, never the password. Anyone could have
 * registered that address first (account pre-hijacking), so everything set on the account
 * before its address was proven is discarded: the password (null, or `''` on a NOT NULL
 * column — both mean "no password"), the two-factor enrolment, the passkeys, and — under
 * the `security` invalidation, always `all` — every session, refresh token, pending
 * challenge and credential one-time secret.
 *
 * The verification is claimed with a conditional update (`… WHERE email_verified_at IS
 * NULL`) in the same transaction as the clean-up, so of two racing email logins exactly one
 * secures the account, and the account is never verified while the old credentials still
 * stand. A password login that loaded the account before the claim mints its pair under
 * the old `token_version`, which the guard and the refresh refuse.
 *
 * @internal step 1 of {@see CompleteFirstFactor}; switch it on through the guard config.
 */
final readonly class SecureClaimedAccount
{
    public function __construct(
        private InvalidateAccountTokens $invalidate,
    ) {}

    /**
     * Whether this call claimed the account (false: it was verified meanwhile — by another
     * email login that secured it, by a verification link or by a password reset).
     */
    public function execute(GuardConfig $guard, Account $account, LoginMethod $method, SessionContext $context): bool
    {
        $model = AccountModels::of($account);
        $column = Columns::emailVerifiedAt();

        $claimed = $model->getConnection()->transaction(function () use ($guard, $account, $model, $column, $method, $context): ?AccountClaimed {
            $won = $model->newQuery()->whereKey($model->getKey())->whereNull($column)->update([$column => $model->freshTimestamp()]) === 1;

            // From here the row is ours (write-locked on a real engine until commit): judge
            // what to remove by what is stored, never by the copy this login loaded earlier.
            $model->refresh();

            if (! $won) {
                return null;
            }

            $passwordRemoved = $account->hasPassword();

            if ($passwordRemoved) {
                AccountState::write($account, [Columns::password() => $this->noPassword($model), Columns::passwordChangedAt() => null]);
            }

            $twoFactorRemoved = $this->removeTwoFactor($model);
            $passkeysRemoved = $this->removePasskeys($guard, $model);
            $revoked = $this->invalidate->execute($guard, $account, InvalidationReason::Security, null, $context)->revoked;

            return new AccountClaimed($guard->name(), $account, $method, $passwordRemoved, $twoFactorRemoved, $passkeysRemoved, $revoked);
        });

        if ($claimed === null) {
            return false;
        }

        event($claimed);

        return true;
    }

    /**
     * `null` where the column allows it (the passwordless state registration creates), else
     * the empty string: the package reads both as "no password" and no hash ever matches it.
     */
    private function noPassword(Model $model): ?string
    {
        foreach ($model->getConnection()->getSchemaBuilder()->getColumns($model->getTable()) as $column) {
            if ($column['name'] === Columns::password()) {
                return $column['nullable'] ? null : '';
            }
        }

        return null;
    }

    private function removeTwoFactor(Model $model): bool
    {
        if (! $model instanceof TwoFactorAuthenticatable || (! $model->hasTwoFactorEnabled() && ! $model->hasPendingTwoFactor())) {
            return false;
        }

        TwoFactor::for($model)->disable();

        return true;
    }

    private function removePasskeys(GuardConfig $guard, Model $model): int
    {
        // With passkeys off nothing can sign in or step up with one (validated at resolution),
        // and the host may not have migrated their table.
        if ($guard->passkeyMode() === PasskeyMode::Off || ! $model instanceof HasPasskeys) {
            return 0;
        }

        $passkeys = Passkeys::for($model)->all();

        foreach ($passkeys as $passkey) {
            Passkeys::for($model)->revoke($passkey);
        }

        return $passkeys->count();
    }
}
