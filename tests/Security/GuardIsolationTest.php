<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Tokens\IssueTokenPair;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardContext;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\ThrottleKey;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

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
]);
