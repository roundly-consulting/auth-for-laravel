<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Tokens\IssueAccountTokens;
use RoundlyConsulting\Auth\Actions\Tokens\IssueTokenPair;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\EmailChangeData;
use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardContext;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\ThrottleKey;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;

/**
 * Users and clients with the SAME primary key: the canonical confusion case.
 */
beforeEach(function (): void {
    $this->user = User::factory()->create();
    $this->client = Client::factory()->create(['id' => $this->user->getKey()]);
});

it('never authenticates a users access token on a clients route, and vice versa', function (): void {
    $userPair = issuePair($this->user);
    $clientPair = issuePair($this->client, 'clients');

    $this->getJson('/clients/auth/me', bearer($userPair))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($clientPair))->assertUnauthorized();

    $this->getJson('/users/auth/me', bearer($userPair))->assertOk()->assertJsonPath('data.email', $this->user->email);
    $this->getJson('/clients/auth/me', bearer($clientPair))->assertOk()->assertJsonPath('data.email', $this->client->email);
});

it('refuses a users refresh token at the clients endpoint without consuming it', function (): void {
    $userPair = issuePair($this->user);

    $this->postJson('/clients/auth/refresh', ['refresh_token' => $userPair->refreshToken])
        ->assertUnauthorized()
        ->assertJsonPath('code', 'refresh_invalid');

    expect(fn () => Authentication::guard('clients')->refresh($userPair->refreshToken, new SessionContext))->toThrow(InvalidRefreshToken::class);

    $this->postJson('/users/auth/refresh', ['refresh_token' => $userPair->refreshToken])->assertOk();
});

it('keys every throttle bucket by guard', function (ThrottleKind $kind): void {
    $keys = app(ThrottleKey::class);
    $registry = app(GuardRegistry::class);

    expect($keys->for($registry->get('users'), $kind, 'a@b.c', '1.1.1.1'))
        ->not->toBe($keys->for($registry->get('clients'), $kind, 'a@b.c', '1.1.1.1'))
        ->not->toContain('a@b.c');
})->with(ThrottleKind::cases());

it('refuses to act on an account of another guard', function (Closure $act): void {
    $pair = issuePair($this->user);
    $clients = Authentication::guard('clients');

    expect(fn () => $act($clients, $this->user))->toThrow(AuthenticationMisconfigured::class, 'belongs to another guard');

    // Nothing happened to the user: the session still works, the account is untouched.
    $this->getJson('/users/auth/me', bearer($pair))->assertOk();
    expect($this->user->fresh()?->isDisabled())->toBeFalse()
        ->and($this->user->fresh()?->tokenVersion())->toBe(0);
})->with([
    'issue tokens' => [fn (GuardContext $guard, User $user) => $guard->issueTokens($user, sessionContext())],
    'issue through the action' => [fn (GuardContext $guard, User $user) => app(IssueTokenPair::class)->execute($guard->config(), $user, LoginMethod::Host, [], sessionContext())],
    'invalidate' => [fn (GuardContext $guard, User $user) => $guard->invalidate($user, InvalidationReason::Security)],
    'logout everywhere' => [fn (GuardContext $guard, User $user) => $guard->logoutEverywhere($user)],
    'logout others' => [fn (GuardContext $guard, User $user) => $guard->logoutOthers($user, new CurrentToken('jti', CarbonImmutable::now()->addMinute()))],
    'logout' => [fn (GuardContext $guard, User $user) => $guard->logout($user, new CurrentToken('jti', CarbonImmutable::now()->addMinute()))],
    'logout a session' => [fn (GuardContext $guard, User $user) => $guard->logoutSession($user, '00000000-0000-0000-0000-000000000000')],
    'sessions' => [fn (GuardContext $guard, User $user) => $guard->sessions($user)],
    'disable' => [fn (GuardContext $guard, User $user) => $guard->disable($user)],
    'enable' => [fn (GuardContext $guard, User $user) => $guard->enable($user)],
    'unlock' => [fn (GuardContext $guard, User $user) => $guard->unlock($user)],
    'lock' => [fn (GuardContext $guard, User $user) => $guard->lock($user)],
    'update locale' => [fn (GuardContext $guard, User $user) => $guard->updateLocale($user, new LocaleData('en'))],
    'activity' => [fn (GuardContext $guard, User $user) => $guard->activity($user)],
    'issue through the host action' => [fn (GuardContext $guard, User $user) => app(IssueAccountTokens::class)->execute($guard->name(), $user, sessionContext())],
    'two-factor status' => [fn (GuardContext $guard, User $user) => $guard->twoFactor()->status($user)],
    'two-factor start' => [fn (GuardContext $guard, User $user) => $guard->twoFactor()->start($user)],
    'two-factor confirm' => [fn (GuardContext $guard, User $user) => $guard->twoFactor()->confirm($user, '123456')],
    'two-factor disable' => [fn (GuardContext $guard, User $user) => $guard->twoFactor()->disable($user)],
    'recovery codes' => [fn (GuardContext $guard, User $user) => $guard->twoFactor()->regenerateRecoveryCodes($user)],
    'passkeys list' => [fn (GuardContext $guard, User $user) => $guard->passkeys()->all($user)],
    'passkey options' => [fn (GuardContext $guard, User $user) => $guard->passkeys()->registrationOptions($user)],
    'passkey register' => [fn (GuardContext $guard, User $user) => $guard->passkeys()->register($user, VirtualAuthenticator::es256()->register(Passkeys::for($user)->registrationOptions()))],
    'passkey rename' => [fn (GuardContext $guard, User $user) => $guard->passkeys()->rename($user, 1, 'x')],
    'passkey remove' => [fn (GuardContext $guard, User $user) => $guard->passkeys()->remove($user, 1)],
    'password set' => [fn (GuardContext $guard, User $user) => $guard->passwords()->set($user, 'a-brand-new-passphrase')],
    'password change' => [fn (GuardContext $guard, User $user) => $guard->passwords()->change($user, new ChangePasswordData('correct-horse-battery', 'a-brand-new-passphrase', new CurrentToken('jti', CarbonImmutable::now()->addMinute()), sessionContext()))],
    'password validate' => [fn (GuardContext $guard, User $user) => $guard->passwords()->validate('a-brand-new-passphrase', $user)],
    'verification send' => [fn (GuardContext $guard, User $user) => $guard->email()->sendVerification($user)],
    'verification request' => [fn (GuardContext $guard, User $user) => $guard->email()->requestVerification($user, sessionContext())],
    'email change' => [fn (GuardContext $guard, User $user) => $guard->email()->requestChange($user, new EmailChangeData('new@example.com', sessionContext()))],
    'reauthentication methods' => [fn (GuardContext $guard, User $user) => $guard->reauthentication()->methods($user)],
    'reauthentication code' => [fn (GuardContext $guard, User $user) => $guard->reauthentication()->sendCode($user, sessionContext())],
    'reauthentication passkey options' => [fn (GuardContext $guard, User $user) => $guard->reauthentication()->passkeyOptions($user, new CurrentToken('jti', CarbonImmutable::now()->addMinute()))],
    'reauthenticate' => [fn (GuardContext $guard, User $user) => $guard->reauthentication()->confirm($user, new ReauthenticationData(ReauthenticationMethod::Password, new CurrentToken('jti', CarbonImmutable::now()->addMinute()), sessionContext(), password: 'correct-horse-battery'))],
    'ensure recent' => [fn (GuardContext $guard, User $user) => $guard->reauthentication()->ensureRecent($user, new CurrentToken('jti', CarbonImmutable::now()->addMinute()))],
    'ensure for' => [fn (GuardContext $guard, User $user) => $guard->reauthentication()->ensureFor(SensitiveAction::DisableTwoFactor, $user, new CurrentToken('jti', CarbonImmutable::now()->addMinute()))],
]);
