<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LogoutScope;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Guards\GuardRegistry;

/**
 * Ends every session of the account: `tv++` (kills every outstanding access token) and
 * every refresh family revoked. The incident-response button.
 */
final readonly class LogoutEverywhere
{
    public function __construct(
        private GuardRegistry $guards,
        private InvalidateAccountTokens $invalidate,
    ) {}

    public function execute(string $guard, Account $account): int
    {
        $config = $this->guards->owning($guard, $account);

        $revoked = $this->invalidate->execute($config, $account, InvalidationReason::Logout, null, new SessionContext)->revoked;

        event(new LoggedOut($guard, $account, LogoutScope::Everywhere, $revoked));

        return $revoked;
    }
}
