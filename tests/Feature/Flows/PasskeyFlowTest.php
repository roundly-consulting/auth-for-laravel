<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Challenges\BeginPasskeyEnrolmentStep;
use RoundlyConsulting\Auth\Actions\Challenges\BeginPasskeyStep;
use RoundlyConsulting\Auth\Actions\Login\CompletePasskeyLogin;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Events\PasskeyAdded;
use RoundlyConsulting\Auth\Events\PasskeyRemoved;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\PasskeyAddedNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Passkeys\Exceptions\CredentialAlreadyRegistered;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;

beforeEach(function (): void {
    Notification::fake();
    $this->user = User::factory()->create();
});

it('logs in passwordless with a real ceremony that required user verification', function (): void {
    $authenticator = registerVirtualPasskey($this->user);

    $options = $this->postJson('/users/auth/login/passkey/options')
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJsonPath('publicKey.userVerification', 'required')
        ->assertJsonPath('publicKey.allowCredentials', [])
        ->json();

    $response = $this->postJson('/users/auth/login/passkey', ['credential' => assertionPayload($authenticator->assert(requestOptionsFrom($options)))], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect(Jwt::verify($response->json('access_token'), 'app-users')->authMethods())->toBe(['hwk', 'user', 'mfa']);
});

it('rejects a presence-only assertion when the passkey must satisfy mfa', function (): void {
    $authenticator = registerVirtualPasskey($this->user);
    $options = Authentication::guard('users')->passkeyLoginOptions(sessionContext());

    expect(fn () => Authentication::guard('users')->loginWithPasskey($authenticator->assert($options, userVerified: false), sessionContext()))
        ->toThrow(InvalidCredentials::class);
});

it('claims no mfa when the guard does not treat a passkey as mfa', function (): void {
    $this->configureGuard('users', ['passkeys.satisfies_mfa' => false]);
    $authenticator = registerVirtualPasskey($this->user);
    $options = Authentication::guard('users')->passkeyLoginOptions(sessionContext());

    $result = Authentication::guard('users')->loginWithPasskey($authenticator->assert($options), sessionContext());

    expect(claimsOf($result->tokens)->authMethods())->toBe(['hwk', 'user']);
});

it('only accepts ceremonies this guard\'s login endpoint started', function (): void {
    $authenticator = registerVirtualPasskey($this->user);
    $foreign = Passkeys::authenticationOptions();

    Authentication::guard('users')->loginWithPasskey($authenticator->assert($foreign), sessionContext());
})->throws(InvalidCredentials::class);

it('refuses another guard\'s passkey before its sign counter moves', function (): void {
    $this->configureGuard('clients', ['passkeys.mode' => 'optional', 'login.passkey' => true]);
    $client = Client::factory()->create(['id' => $this->user->getKey()]);
    $authenticator = registerVirtualPasskey($client);
    $before = Passkey::query()->sole()->sign_count;

    $options = Authentication::guard('users')->passkeyLoginOptions(sessionContext());

    expect(fn () => app(CompletePasskeyLogin::class)->execute('users', $authenticator->assert($options), sessionContext()))->toThrow(InvalidCredentials::class)
        ->and(Passkey::query()->sole()->sign_count)->toBe($before);

    $clientOptions = Authentication::guard('clients')->passkeyLoginOptions(sessionContext());
    expect(Authentication::guard('clients')->loginWithPasskey($authenticator->assert($clientOptions), sessionContext())->isAuthenticated())->toBeTrue();
});

it('uses a passkey as the second factor, bound to the challenge ceremony', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required_when_enrolled']);
    $authenticator = registerVirtualPasskey($this->user);
    $token = $this->postJson('/users/auth/login', ['identifier' => $this->user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertJsonPath('remaining.0.step', 'passkey')
        ->json('challenge_token');

    // An assertion for some other ceremony cannot complete this one.
    $stray = $authenticator->assert(Passkeys::for($this->user)->authenticationOptions());
    $this->postJson('/users/auth/challenge/passkey', ['challenge_token' => $token, 'credential' => assertionPayload($stray)], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'factor_failed');

    $options = $this->postJson('/users/auth/challenge/passkey/options', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])->assertOk()->json();

    $response = $this->postJson('/users/auth/challenge/passkey', ['challenge_token' => $token, 'credential' => assertionPayload($authenticator->assert(requestOptionsFrom($options)))], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect(Jwt::verify($response->json('access_token'), 'app-users')->authMethods())->toBe(['pwd', 'hwk', 'mfa']);
});

it('refuses another account\'s passkey in a challenge', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required_when_enrolled']);
    registerVirtualPasskey($this->user);
    $intruder = registerVirtualPasskey(User::factory()->create());
    $token = $this->postJson('/users/auth/login', ['identifier' => $this->user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => 'PestBrowser/1.0'])->json('challenge_token');

    $options = $this->postJson('/users/auth/challenge/passkey/options', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])->json();

    $this->postJson('/users/auth/challenge/passkey', ['challenge_token' => $token, 'credential' => assertionPayload($intruder->assert(requestOptionsFrom($options)))], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('attempts_left', 4);
});

it('forces passkey enrolment inside the challenge', function (): void {
    Event::fake([PasskeyAdded::class]);
    $this->configureGuard('users', ['passkeys.second_factor' => 'required']);
    $token = $this->postJson('/users/auth/login', ['identifier' => $this->user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertJsonPath('remaining.0.step', 'enrol_passkey')
        ->json('challenge_token');

    $this->postJson('/users/auth/challenge/passkey/enrol/options', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])->assertOk()->assertJsonStructure(['ceremonyId', 'publicKey' => ['challenge', 'user']]);

    $options = app(BeginPasskeyEnrolmentStep::class)->execute('users', $token, sessionContext());
    $attestation = VirtualAuthenticator::es256()->register($options);

    $this->postJson('/users/auth/challenge/passkey/enrol', ['challenge_token' => $token, 'credential' => attestationPayload($attestation), 'name' => 'Laptop'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect(Passkey::query()->sole()->name)->toBe('Laptop');
    Event::assertDispatched(PasskeyAdded::class);
    Notification::assertSentTo($this->user, PasskeyAddedNotification::class);
});

it('manages passkeys over http', function (): void {
    Event::fake([PasskeyAdded::class, PasskeyRemoved::class]);
    $pair = issuePair($this->user);

    $this->postJson('/users/auth/passkeys/options', [], bearer($pair))->assertOk()->assertJsonStructure(['ceremonyId', 'publicKey']);
    $attestation = VirtualAuthenticator::es256()->register(Passkeys::for($this->user)->registrationOptions());

    $id = $this->postJson('/users/auth/passkeys', ['credential' => attestationPayload($attestation), 'name' => 'Phone'], bearer($pair))
        ->assertCreated()
        ->assertJsonPath('passkey.name', 'Phone')
        ->assertJsonPath('tokens', null)
        ->json('passkey.id');

    // The account now has a passkey: the password login no longer satisfies the gate.
    $this->deleteJson("/users/auth/passkeys/{$id}", [], bearer($pair))->assertForbidden()->assertJsonPath('methods', ['passkey']);
    $pair = issuePair($this->user, amr: [AuthMethodReference::Hwk, AuthMethodReference::User, AuthMethodReference::Mfa]);

    $this->getJson('/users/auth/passkeys', bearer($pair))->assertOk()->assertJsonCount(1, 'data');
    $this->patchJson("/users/auth/passkeys/{$id}", ['name' => 'Work phone'], bearer($pair))->assertOk()->assertJsonPath('data.name', 'Work phone');
    $this->patchJson('/users/auth/passkeys/abc', ['name' => 'x'], bearer($pair))->assertNotFound();
    $this->deleteJson('/users/auth/passkeys/999999', [], bearer($pair))->assertNotFound();
    $this->deleteJson('/users/auth/passkeys/abc', [], bearer($pair))->assertNotFound();

    $this->deleteJson("/users/auth/passkeys/{$id}", [], bearer($pair))->assertOk()->assertJsonPath('status', 'removed');

    expect(Passkey::query()->count())->toBe(0);
    Event::assertDispatched(PasskeyRemoved::class);
});

it('refuses to register a credential twice', function (): void {
    $pair = issuePair($this->user);
    Passkeys::fake()->failRegistrationWith(CredentialAlreadyRegistered::make());

    $attestation = VirtualAuthenticator::es256()->register(Passkeys::for($this->user)->registrationOptions());

    $this->postJson('/users/auth/passkeys', ['credential' => attestationPayload($attestation)], bearer($pair))
        ->assertStatus(422)
        ->assertJsonPath('code', 'passkey_registration_failed');
});

it('rejects a malformed credential payload', function (): void {
    $this->postJson('/users/auth/login/passkey', ['credential' => ['response' => 'x']])->assertStatus(422)->assertJsonValidationErrors('credential');
});

it('protects the last passkey when it is the only way in', function (): void {
    $this->configureGuard('users', ['login.password' => false, 'login.magic_link' => false, 'login.email_otp' => false]);
    registerVirtualPasskey($this->user);
    $pair = issuePair($this->user, amr: [AuthMethodReference::Hwk, AuthMethodReference::User, AuthMethodReference::Mfa]);

    $this->deleteJson('/users/auth/passkeys/'.Passkey::query()->sole()->getKey(), [], bearer($pair))
        ->assertStatus(409)
        ->assertJsonPath('code', 'last_credential');
});

it('reauthenticates with a passkey bound to the session', function (): void {
    $this->configureGuard('users', ['tokens.access_ttl' => 7200]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
    $authenticator = registerVirtualPasskey($this->user);
    $pair = issuePair($this->user);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    $options = $this->postJson('/users/auth/reauthenticate/passkey/options', [], bearer($pair))->assertOk()->json();

    $this->postJson('/users/auth/reauthenticate', ['method' => 'passkey', 'credential' => assertionPayload($authenticator->assert(requestOptionsFrom($options)))], bearer($pair))
        ->assertOk();

    $this->postJson('/users/auth/reauthenticate', ['method' => 'passkey', 'credential' => assertionPayload($authenticator->assert(requestOptionsFrom($options)))], bearer($pair))
        ->assertStatus(422);
    CarbonImmutable::setTestNow();
});

it('walks a two-step challenge: passkey first, then totp', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required', 'two_factor.passkey_satisfies_required' => false]);
    $secret = enableTotp($this->user);
    $authenticator = registerVirtualPasskey($this->user);

    $pending = Authentication::guard('users')->attempt(new PasswordCredentials($this->user->email, 'correct-horse-battery'), sessionContext())->challenge;
    $options = app(BeginPasskeyStep::class)->execute('users', $pending->token, sessionContext());

    $halfway = Authentication::guard('users')->completeChallenge(new ChallengeFactorData($pending->token, FactorMethod::Passkey, sessionContext(), assertion: $authenticator->assert($options)));

    expect($halfway->requiresChallenge())->toBeTrue()
        ->and(array_map(fn ($step) => $step->value, $halfway->challenge->completed))->toBe(['passkey'])
        ->and($halfway->challenge->remaining[0]->step->value)->toBe('second_factor')
        ->and($halfway->challenge->token)->toBe($pending->token);

    $done = Authentication::guard('users')->completeChallenge(new ChallengeFactorData($pending->token, FactorMethod::Totp, sessionContext(), code: totpCode($secret)));

    expect($done->isAuthenticated())->toBeTrue()
        ->and(claimsOf($done->tokens)->authMethods())->toBe(['pwd', 'hwk', 'otp', 'mfa']);
});

it('counts a failed passkey enrolment and refuses a stray ceremony', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required']);
    $pending = Authentication::guard('users')->attempt(new PasswordCredentials($this->user->email, 'correct-horse-battery'), sessionContext())->challenge;
    $stray = VirtualAuthenticator::es256()->register(Passkeys::for($this->user)->registrationOptions());

    expect(fn () => Authentication::guard('users')->completeChallenge(new ChallengeFactorData($pending->token, FactorMethod::PasskeyEnrolment, sessionContext(), attestation: $stray)))
        ->toThrow(ChallengeFactorFailed::class);

    $options = app(BeginPasskeyEnrolmentStep::class)->execute('users', $pending->token, sessionContext());
    Passkeys::fake()->failRegistrationWith(CredentialAlreadyRegistered::make());

    expect(fn () => Authentication::guard('users')->completeChallenge(new ChallengeFactorData($pending->token, FactorMethod::PasskeyEnrolment, sessionContext(), attestation: VirtualAuthenticator::es256()->register($options))))
        ->toThrow(ChallengeFactorFailed::class);
});

it('refuses forced passkey enrolment for an unverified address', function (): void {
    $this->configureGuard('users', ['passkeys.second_factor' => 'required', 'challenge.enrolment_requires_verified_email' => false]);
    $user = User::factory()->unverified()->create();
    $pending = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->challenge;

    $this->configureGuard('users', ['challenge.enrolment_requires_verified_email' => true]);

    app(BeginPasskeyEnrolmentStep::class)->execute('users', $pending->token, sessionContext());
})->throws(EnrolmentRequired::class);
