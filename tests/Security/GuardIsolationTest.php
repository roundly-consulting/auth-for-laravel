<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Facades\Authentication;
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
