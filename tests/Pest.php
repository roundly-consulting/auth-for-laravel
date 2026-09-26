<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\ConfigMerger;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\TestCase;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

uses(TestCase::class)->in(__DIR__);

/**
 * @param  array<string, mixed>  $overrides
 */
function guardConfig(array $overrides = [], string $name = 'users'): GuardConfig
{
    /** @var array<string, mixed> $defaults */
    $defaults = config('authentication.defaults');

    /** @var array<string, mixed> $merged */
    $merged = ConfigMerger::merge($defaults, ['model' => User::class, ...$overrides]);

    return new GuardConfig($name, $merged);
}

/**
 * A real token pair for an account, minted through the package.
 *
 * @param  list<AuthMethodReference>  $amr
 */
function issuePair(Account $account, string $guard = 'users', array $amr = [AuthMethodReference::Pwd], ?SessionContext $context = null): TokenPair
{
    return Authentication::guard($guard)
        ->issueTokens($account, $context ?? new SessionContext('10.0.0.1', 'PestBrowser/1.0'), LoginMethod::Password, $amr);
}

/**
 * @return array<string, string>
 */
function bearer(TokenPair $pair): array
{
    return ['Authorization' => 'Bearer '.$pair->accessToken, 'User-Agent' => 'PestBrowser/1.0'];
}

function claimsOf(TokenPair $pair, string $audience = 'app-users'): Claims
{
    return Jwt::verify($pair->accessToken, $audience);
}

/**
 * Give an account a confirmed TOTP enrolment; returns the base32 secret.
 */
function enableTotp(Model $account): string
{
    $secret = TwoFactor::generateSecret();
    $codes = TwoFactor::generateRecoveryCodes(3);

    $account->forceFill([
        'two_factor_secret' => $secret,
        'two_factor_recovery_codes' => array_map(static fn (string $code): string => Hash::make($code), $codes),
        'two_factor_confirmed_at' => now(),
    ])->save();

    $GLOBALS['authentication_test_recovery_codes'] = $codes;

    return $secret;
}

function totpCode(string $secret, int $offset = 0): string
{
    return TwoFactor::currentCode($secret, time() + $offset);
}

function addPasskey(Model $account): Passkey
{
    /** @var Passkey $passkey */
    $passkey = Passkey::factory()->create([
        'authenticatable_type' => $account->getMorphClass(),
        'authenticatable_id' => $account->getKey(),
    ]);

    return $passkey;
}

function sessionContext(string $userAgent = 'PestBrowser/1.0', ?string $ip = '10.0.0.1', ?string $deviceId = null): SessionContext
{
    return new SessionContext($ip, $userAgent, $deviceId);
}

/**
 * The plaintext recovery codes of the last enableTotp() call.
 *
 * @return list<string>
 */
function recoveryCodes(): array
{
    return $GLOBALS['authentication_test_recovery_codes'] ?? [];
}
