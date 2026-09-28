<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\AccountDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Disables an account: every session and access token dies (never configurable below
 * `all`), and it can no longer log in or refresh.
 */
final readonly class DisableAccount
{
    public function __construct(
        private GuardRegistry $guards,
        private InvalidateAccountTokens $invalidate,
    ) {}

    public function execute(string $guard, Account $account, ?string $reason = null): void
    {
        $config = $this->guards->owning($guard, $account);

        AccountState::write($account, [
            Columns::disabledAt() => CarbonImmutable::now(),
            Columns::disabledReason() => $reason === null ? null : mb_substr($reason, 0, 255),
        ]);

        $this->invalidate->execute($config, $account, InvalidationReason::AccountDisabled, null, new SessionContext);

        event(new AccountDisabled($guard, $account, $reason));
    }
}
