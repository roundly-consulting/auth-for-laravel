<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Exceptions\ReauthenticationRequired;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;

/**
 * Passes when the calling session re-authenticated within the window — or, with
 * `fresh_login_counts`, when the token's `auth_time` itself is that recent (a user who
 * just logged in is not asked again). Either proof must meet the account's CURRENT
 * requirement: an account with TOTP or a passkey (under
 * `require_second_factor_when_enrolled`) needs a second-factor proof — a password or
 * email-code re-authentication, or a login that skipped the factor, does not count, even
 * if it happened before the factor was enrolled. Otherwise 403
 * `reauthentication_required` with the methods this account may use.
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
    public function execute(string $guard, CurrentToken $current, Account $account, ?int $seconds = null): void
    {
        $config = $this->guards->get($guard);
        $window = CarbonImmutable::now()->subSeconds($seconds ?? $config->reauthenticationTimeout());
        $secondFactor = ReauthenticationMethods::requireSecondFactor($config, $account);

        if ($config->freshLoginCountsAsReauthentication()
            && $current->authTime !== null
            && $current->authTime->greaterThanOrEqualTo($window)
            && (! $secondFactor || AuthMethodReference::provesSecondFactor($current->authMethods))) {
            return;
        }

        $proof = $this->marker->proof($guard, $current->sessionKey());

        if ($proof !== null
            && $proof->at->greaterThanOrEqualTo($window)
            && (! $secondFactor || $proof->method->isSecondFactor())) {
            return;
        }

        throw ReauthenticationRequired::using(ReauthenticationMethods::available($config, $account));
    }
}
