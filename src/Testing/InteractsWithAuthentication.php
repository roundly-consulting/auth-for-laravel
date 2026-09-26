<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Testing;

use PHPUnit\Framework\Assert;
use RoundlyConsulting\Auth\Actions\Tokens\IssueTokenPair;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;

/**
 * Test helpers for host applications (use it in your Laravel TestCase). `actingAsAccount`
 * mints a REAL token pair and sends it as the bearer token, so requests run through the
 * real jwt guard, audience, denylist and token-version checks.
 */
trait InteractsWithAuthentication
{
    protected ?TokenPair $authenticationTokens = null;

    /**
     * Each account's token version when {@see self::actingAsAccount()} signed it in — the
     * baseline {@see self::assertTokensInvalidated()} compares against.
     *
     * @var array<string, int>
     */
    protected array $authenticationTokenVersions = [];

    /**
     * Provided by Laravel's (and Testbench's) HTTP testing concern.
     *
     * @return $this
     */
    abstract public function withHeader(string $name, string $value);

    /**
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function actingAsAccount(Account $account, ?string $guard = null, array $authMethods = [AuthMethodReference::Pwd]): static
    {
        $config = app(GuardRegistry::class)->get($guard);

        $this->authenticationTokenVersions[$this->authenticationAccountKey($account)] = $this->freshAccount($account)->tokenVersion();

        $this->authenticationTokens = app(IssueTokenPair::class)->execute(
            $config,
            $account,
            LoginMethod::Host,
            $authMethods,
            new SessionContext('127.0.0.1', 'Testing'),
        );

        return $this->withHeader('Authorization', 'Bearer '.$this->authenticationTokens->accessToken);
    }

    public function assertLoginActivity(string $guard, ActivityType $type, ActivityOutcome $outcome): static
    {
        Assert::assertTrue(
            Models::loginActivities()->where('guard', $guard)->where('type', $type->value)->where('outcome', $outcome->value)->exists(),
            "No [{$guard}] login activity of type [{$type->value}] with outcome [{$outcome->value}] was recorded.",
        );

        return $this;
    }

    /**
     * The account's tokens were invalidated per the guard's scope for the reason, since
     * `$since` (default: the version when {@see self::actingAsAccount()} signed it in):
     * its token version moved — and under `all` no session survived — or, for a reason
     * whose scope is `none`, it did not move.
     */
    public function assertTokensInvalidated(Account $account, InvalidationReason $reason, ?string $guard = null, ?int $since = null): static
    {
        $baseline = $since ?? $this->authenticationTokenVersions[$this->authenticationAccountKey($account)] ?? null;

        if ($baseline === null) {
            Assert::fail('No token-version baseline for the account: call actingAsAccount() before the change, or pass `since:`.');
        }

        $version = $this->freshAccount($account)->tokenVersion();
        $scope = app(GuardRegistry::class)->get($guard)->invalidationScope($reason);

        if ($scope === InvalidationScope::None) {
            Assert::assertSame($baseline, $version, "The account token version moved although [{$reason->value}] has scope [none].");

            return $this;
        }

        Assert::assertGreaterThan($baseline, $version, "The account token version did not move since {$baseline}.");

        if ($scope === InvalidationScope::All) {
            Assert::assertCount(0, RefreshToken::listFor(AccountModels::of($account)), 'Sessions survived an invalidation with scope [all].');
        }

        return $this;
    }

    private function freshAccount(Account $account): Account
    {
        $model = AccountModels::of($account);
        $fresh = $model->newQuery()->whereKey($model->getKey())->first();

        Assert::assertInstanceOf(Account::class, $fresh);

        return $fresh;
    }

    private function authenticationAccountKey(Account $account): string
    {
        $model = AccountModels::of($account);

        return $model->getMorphClass().':'.$model->getKey();
    }
}
