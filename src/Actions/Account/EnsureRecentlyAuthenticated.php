<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Exceptions\ReauthenticationRequired;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;

/**
 * Passes when the calling session re-authenticated within the window — or, with
 * `fresh_login_counts`, when the token's `auth_time` itself is that recent (a user who
 * just logged in is not asked again). Otherwise 403 `reauthentication_required` with
 * the methods this account may use.
 */
final readonly class EnsureRecentlyAuthenticated
{
    public function __construct(
        private GuardRegistry $guards,
        private ReauthenticationMarker $marker,
    ) {}

    /**
     * @throws ReauthenticationRequired
     */
    public function execute(string $guard, CurrentToken $current, ?int $seconds = null, ?Account $account = null): void
    {
        $config = $this->guards->get($guard);
        $window = CarbonImmutable::now()->subSeconds($seconds ?? $config->reauthenticationTimeout());

        if ($config->freshLoginCountsAsReauthentication() && $current->authTime !== null && $current->authTime->greaterThanOrEqualTo($window)) {
            return;
        }

        $at = $this->marker->at($guard, $current->sessionKey());

        if ($at !== null && $at->greaterThanOrEqualTo($window)) {
            return;
        }

        throw ReauthenticationRequired::using($account === null ? $config->reauthenticationMethods() : ReauthenticationMethods::available($config, $account));
    }
}
