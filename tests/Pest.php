<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\ConfigMerger;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\SwappedModelsTestCase;
use RoundlyConsulting\Auth\Tests\TestCase;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

uses(TestCase::class)->in('Arch', 'Commands', 'Concurrency', 'Config', 'Feature', 'Migrations', 'Models', 'Security', 'Unit');

// The swap suite boots with the four models swapped for host subclasses.
uses(SwappedModelsTestCase::class)->in('Swaps');

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
    return TwoFactor::currentCode($secret, CarbonImmutable::now()->getTimestamp() + $offset);
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

/**
 * The last notification of a class sent to a notifiable (Notification::fake() active).
 *
 * @template T of \RoundlyConsulting\Auth\Notifications\AuthenticationNotification
 *
 * @param  class-string<T>  $class
 * @return T
 */
function sentNotification(object $notifiable, string $class): AuthenticationNotification
{
    $sent = Notification::sent($notifiable, $class);

    expect($sent)->not->toBeEmpty();

    return $sent->last();
}

/**
 * The secret carried in an emailed URL's fragment (`#token=…`).
 */
function tokenFromUrl(?string $url): string
{
    expect($url)->toBeString()->toContain('#token=');

    return rawurldecode((string) substr((string) strstr((string) $url, '#token='), 7));
}

/**
 * Register a real credential for an account through a virtual authenticator.
 */
function registerVirtualPasskey(Model&HasPasskeys $account): VirtualAuthenticator
{
    $authenticator = VirtualAuthenticator::es256();

    Passkeys::for($account)->register($authenticator->register(Passkeys::for($account)->registrationOptions()));

    return $authenticator;
}

/**
 * The browser JSON of an assertion (base64url members), as a client would POST it.
 *
 * @return array<string, mixed>
 */
function assertionPayload(AuthenticationResponseData $response): array
{
    $b64 = static fn (string $bytes): string => Base64Url::encode($bytes);

    return [
        'id' => $b64($response->rawId),
        'rawId' => $b64($response->rawId),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => $b64($response->clientDataJson),
            'authenticatorData' => $b64($response->authenticatorData),
            'signature' => $b64($response->signature),
            'userHandle' => $response->userHandle === null ? null : $b64($response->userHandle),
        ],
        'ceremonyId' => $response->ceremonyId,
    ];
}

/**
 * @return array<string, mixed>
 */
function attestationPayload(RegistrationResponseData $response): array
{
    $b64 = static fn (string $bytes): string => Base64Url::encode($bytes);

    return [
        'id' => $b64($response->rawId),
        'rawId' => $b64($response->rawId),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => $b64($response->clientDataJson),
            'attestationObject' => $b64($response->attestationObject),
            'transports' => $response->transports,
        ],
        'ceremonyId' => $response->ceremonyId,
    ];
}

/**
 * Request options rebuilt from the JSON an options endpoint returned.
 *
 * @param  array<string, mixed>  $json
 */
function requestOptionsFrom(array $json): RequestOptionsData
{
    return new RequestOptionsData(
        ceremonyId: $json['ceremonyId'],
        rpId: $json['publicKey']['rpId'],
        challenge: $json['publicKey']['challenge'],
        timeoutMs: $json['publicKey']['timeout'],
        userVerification: UserVerification::from($json['publicKey']['userVerification']),
    );
}
