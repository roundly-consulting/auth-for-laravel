<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Challenges\FindActiveChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;
use RoundlyConsulting\Auth\Events\AccountTokensInvalidated;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

it('applies each scope to access tokens, refresh tokens, challenges and login links', function (InvalidationReason $reason, string $scope, InvalidationScope $applied): void {
    Event::fake([AccountTokensInvalidated::class]);
    $key = match ($reason) {
        InvalidationReason::PasswordChanged => 'password_changed',
        InvalidationReason::EmailChanged => 'email_changed',
        InvalidationReason::TwoFactorChanged => 'two_factor_changed',
        default => 'passkey_changed',
    };
    $this->configureGuard('users', ["invalidation.{$key}" => $scope]);

    $user = User::factory()->create();
    enableTotp($user);
    $current = issuePair($user);
    $other = issuePair($user);
    $challenge = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->challenge;
    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());
    $link = tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url);

    $tokens = Authentication::guard('users')->invalidate($user, $reason, CurrentToken::fromClaims(claimsOf($current)), sessionContext());

    $this->getJson('/users/auth/me', bearer($current))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($other))->assertUnauthorized();
    expect(fn () => Authentication::guard('users')->refresh($other->refreshToken, sessionContext()))->toThrow(InvalidRefreshToken::class)
        ->and(fn () => app(FindActiveChallenge::class)->execute('users', $challenge->token, sessionContext()))->toThrow(ChallengeInvalid::class)
        ->and(fn () => Authentication::guard('users')->consumeMagicLink($link, sessionContext()))->toThrow(InvalidOneTimeToken::class);

    if ($applied === InvalidationScope::Others) {
        $this->getJson('/users/auth/me', bearer($tokens))->assertOk();
        expect(claimsOf($tokens)->authMethods())->toBe(['pwd'])
            ->and(claimsOf($tokens)->authTime())->toBe(claimsOf($current)->authTime());
    } else {
        expect($tokens)->toBeNull();
    }

    Event::assertDispatched(AccountTokensInvalidated::class, fn (AccountTokensInvalidated $event): bool => $event->scope === $applied && $event->revoked === 2);
})->with([
    'password changed, others' => [InvalidationReason::PasswordChanged, 'others', InvalidationScope::Others],
    'password changed, all' => [InvalidationReason::PasswordChanged, 'all', InvalidationScope::All],
    'email changed, others' => [InvalidationReason::EmailChanged, 'others', InvalidationScope::Others],
    '2fa changed, all' => [InvalidationReason::TwoFactorChanged, 'all', InvalidationScope::All],
    'passkey changed, others' => [InvalidationReason::PasskeyChanged, 'others', InvalidationScope::Others],
]);

it('leaves everything alone under none — except login links after resets, disables and email changes', function (): void {
    $this->configureGuard('users', ['invalidation.passkey_changed' => 'none', 'invalidation.email_changed' => 'none']);
    $user = User::factory()->create();
    $pair = issuePair($user);

    expect(Authentication::guard('users')->invalidate($user, InvalidationReason::PasskeyChanged))->toBeNull();
    $this->getJson('/users/auth/me', bearer($pair))->assertOk();

    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());
    $link = tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url);

    Authentication::guard('users')->invalidate($user, InvalidationReason::EmailChanged);

    $this->getJson('/users/auth/me', bearer($pair))->assertOk();
    expect(fn () => Authentication::guard('users')->consumeMagicLink($link, sessionContext()))->toThrow(InvalidOneTimeToken::class);
});

it('treats others without a current device as all', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    expect(Authentication::guard('users')->invalidate($user, InvalidationReason::PasswordChanged))->toBeNull();
    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
});
