<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Auth\Actions\Tokens\IssueAccountTokens;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

it('issues a host-vouched pair and announces it', function (): void {
    Event::fake([TokensIssued::class]);
    $user = User::factory()->create();

    $pair = app(IssueAccountTokens::class)->execute('users', $user, sessionContext(), LoginMethod::Host, [AuthMethodReference::Mfa]);

    expect(claimsOf($pair)->authMethods())->toBe(['mfa'])
        ->and(claimsOf($pair)->sessionId())->toBe($pair->sessionId);
    Event::assertDispatched(TokensIssued::class, fn (TokensIssued $event): bool => $event->guard === 'users'
        && $event->jti === $pair->accessTokenId
        && $event->method === LoginMethod::Host
        && $event->account->is($user));
});

it('refuses another guard\'s account before minting anything', function (): void {
    Event::fake([TokensIssued::class]);

    expect(fn () => app(IssueAccountTokens::class)->execute('users', Client::factory()->create(), sessionContext()))
        ->toThrow(AuthenticationMisconfigured::class);

    expect(RefreshToken::query()->count())->toBe(0);
    Event::assertNotDispatched(TokensIssued::class);
});
