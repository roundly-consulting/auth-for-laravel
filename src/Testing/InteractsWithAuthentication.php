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
     * The account's tokens were invalidated per the guard's scope for the reason: its
     * token version moved, and under `all` no session survived.
     */
    public function assertTokensInvalidated(Account $account, InvalidationReason $reason, ?string $guard = null): static
    {
        $model = AccountModels::of($account);
        $fresh = $model->newQuery()->whereKey($model->getKey())->first();
        $scope = app(GuardRegistry::class)->get($guard)->invalidationScope($reason);

        Assert::assertInstanceOf(Account::class, $fresh);
        Assert::assertGreaterThan(0, $fresh->tokenVersion(), 'The account token version never moved.');

        if ($scope === InvalidationScope::All) {
            Assert::assertCount(0, RefreshToken::listFor($model), 'Sessions survived an invalidation with scope [all].');
        }

        return $this;
    }
}
