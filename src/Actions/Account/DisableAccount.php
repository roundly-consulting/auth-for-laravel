<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\AccountDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Actors;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Disables an account: every session and access token dies (never configurable below
 * `all`), and it can no longer log in or refresh. `$actor` (the admin) goes on the
 * event; no notification is sent.
 */
final readonly class DisableAccount
{
    public function __construct(
        private GuardRegistry $guards,
        private InvalidateAccountTokens $invalidate,
    ) {}

    public function execute(string $guard, Account $account, ?string $reason = null, ?Model $actor = null): void
    {
        $config = $this->guards->owning($guard, $account);
        $actor = Actors::other($account, $actor);

        AccountState::write($account, [
            Columns::disabledAt() => CarbonImmutable::now(),
            Columns::disabledReason() => $reason === null ? null : mb_substr($reason, 0, 255),
        ]);

        $this->invalidate->execute($config, $account, InvalidationReason::AccountDisabled, null, new SessionContext);

        event(new AccountDisabled($guard, $account, $reason, $actor));
    }
}
