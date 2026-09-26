<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Email;

use Carbon\CarbonImmutable;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\ConsumeOneTimeToken;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\InvalidateOneTimeTokens;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Events\EmailChanged;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use SensitiveParameter;

/**
 * Confirms an email change from the link mailed to the NEW address (guest-callable —
 * it is opened from a mail client). The address is re-checked in a transaction (another
 * account may have claimed it meanwhile) and the account's email must still be the one
 * the change started from, and the account must not be disabled. Every other outstanding
 * link of the account dies (they went to the old address), the account's tokens are
 * invalidated, and the old address is told.
 */
final readonly class ConfirmEmailChange
{
    public function __construct(
        private GuardRegistry $guards,
        private ConsumeOneTimeToken $consume,
        private InvalidateOneTimeTokens $invalidateTokens,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $token, SessionContext $context): Account
    {
        $config = $this->guards->get($guard);

        if (! $config->emailChangeEnabled()) {
            throw new LoginMethodDisabled;
        }

        $redeemed = $this->consume->execute($guard, OneTimeTokenPurpose::EmailChange, $token, $context);
        $account = $redeemed->account;

        // A disabled account changes nothing (invalidation kills its links; host code
        // that disables around the package must not leave one working).
        if ($account->isDisabled()) {
            throw new InvalidOneTimeToken;
        }
        $accounts = new AccountRepository($config);
        $new = $redeemed->record->email;
        $old = (string) $account->accountEmail();
        $expected = $redeemed->record->payloadValue('old_email');

        if (! is_string($expected) || $accounts->normalizeEmail($expected) !== $accounts->normalizeEmail($old)) {
            throw new InvalidOneTimeToken;
        }

        $model = AccountModels::of($account);

        try {
            $model->getConnection()->transaction(function () use ($accounts, $account, $config, $new): void {
                $holder = $accounts->findByEmail($new, withTrashed: true);

                if ($holder !== null && $holder->getAuthIdentifier() !== $account->getAuthIdentifier()) {
                    throw new InvalidOneTimeToken;
                }

                AccountState::write($account, [
                    $config->emailColumn() => $new,
                    Columns::emailVerifiedAt() => CarbonImmutable::now(),
                ]);
            });
        } catch (UniqueConstraintViolationException $e) {
            throw new InvalidOneTimeToken($e);
        }

        $this->invalidateTokens->execute($guard, $account);
        $this->invalidate->execute($config, $account, InvalidationReason::EmailChanged, null, $context);

        $this->notifications->sendTo($config, NotificationType::EmailChanged, $old, new NotificationData(
            guard: $guard,
            replacements: ['new_email' => $new],
        ), $account->preferredLocale());

        event(new EmailChanged($guard, $account, $old, $new));

        return $account;
    }
}
