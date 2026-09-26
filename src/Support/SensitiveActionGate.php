<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Actions\Account\EnsureRecentlyAuthenticated;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Exceptions\ReauthenticationRequired;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Requires a recent re-authentication for the actions listed in the guard's
 * `reauthentication.required_for`.
 */
final readonly class SensitiveActionGate
{
    public function __construct(private EnsureRecentlyAuthenticated $ensureRecent) {}

    /**
     * @throws ReauthenticationRequired
     */
    public function check(GuardConfig $guard, SensitiveAction $action, CurrentToken $current, Account $account): void
    {
        if ($guard->requiresReauthentication($action)) {
            $this->ensureRecent->execute($guard->name(), $current, $account);
        }
    }
}
