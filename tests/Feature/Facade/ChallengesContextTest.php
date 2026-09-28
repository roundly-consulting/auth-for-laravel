<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;

beforeEach(function (): void {
    Notification::fake();
});

function pendingChallengeFor(User $user): PendingChallenge
{
    $result = Authentication::attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect($result->requiresChallenge())->toBeTrue();

    return $result->challenge ?? throw new RuntimeException('no challenge');
}

it('completes a totp step', function (): void {
    $user = User::factory()->create();
    $secret = enableTotp($user);
    $pending = pendingChallengeFor($user);

    $result = Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::Totp, sessionContext(), code: totpCode($secret)));

    expect($result->isAuthenticated())->toBeTrue();
});

it('runs the forced totp enrolment of a challenge', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $user = User::factory()->create();
    $pending = pendingChallengeFor($user);

    $setup = Authentication::challenges()->startTwoFactorEnrolment($pending->token, sessionContext());
    $result = Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::TotpEnrolment, sessionContext(), code: totpCode($setup->secret)));

    expect($result->isAuthenticated())->toBeTrue()
        ->and($user->fresh()?->hasTwoFactorEnabled())->toBeTrue();
});

it('runs a passkey second factor', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required_when_enrolled']);
    $user = User::factory()->create();
    $authenticator = registerVirtualPasskey($user);
    $pending = pendingChallengeFor($user);

    $options = Authentication::challenges()->passkeyOptions($pending->token, sessionContext());
    $result = Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::Passkey, sessionContext(), assertion: $authenticator->assert($options)));

    expect($result->isAuthenticated())->toBeTrue();
});

it('runs a forced passkey enrolment', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required']);
    $user = User::factory()->create();
    $pending = pendingChallengeFor($user);

    $options = Authentication::challenges()->passkeyEnrolmentOptions($pending->token, sessionContext());
    $result = Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::PasskeyEnrolment, sessionContext(), attestation: VirtualAuthenticator::es256()->register($options), passkeyName: 'Laptop'));

    expect($result->isAuthenticated())->toBeTrue()
        ->and($user->passkeys()->sole()->name)->toBe('Laptop');
});

it('refuses another guard\'s challenge token', function (Closure $act): void {
    $user = User::factory()->create();
    enableTotp($user);
    $pending = pendingChallengeFor($user);

    expect(fn () => $act($pending->token))->toThrow(ChallengeInvalid::class);
})->with([
    'complete' => [fn (string $token) => Authentication::guard('clients')->challenges()->complete(new ChallengeFactorData($token, FactorMethod::Totp, sessionContext(), code: '000000'))],
    'passkey options' => [fn (string $token) => Authentication::guard('clients')->challenges()->passkeyOptions($token, sessionContext())],
    'passkey enrolment options' => [fn (string $token) => Authentication::guard('clients')->challenges()->passkeyEnrolmentOptions($token, sessionContext())],
    'totp enrolment' => [fn (string $token) => Authentication::guard('clients')->challenges()->startTwoFactorEnrolment($token, sessionContext())],
]);
