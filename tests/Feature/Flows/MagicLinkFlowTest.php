<?php

declare(strict_types=1);

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Events\MagicLinkRequested;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\PlainAccount;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

function requestLink(User|Client $account, string $guard = 'users'): string
{
    Authentication::guard($guard)->requestMagicLink($account->email, sessionContext());

    return tokenFromUrl(sentNotification($account, MagicLinkNotification::class)->data->url);
}

it('mails a fragment link and signs in with it', function (): void {
    Event::fake([MagicLinkRequested::class]);
    $user = User::factory()->unverified()->create();

    $this->postJson('/users/auth/login/magic-link', ['email' => strtoupper($user->email)])
        ->assertStatus(202)
        ->assertExactJson(['status' => 'sent']);

    $url = sentNotification($user, MagicLinkNotification::class)->data->url;
    expect($url)->toStartWith('https://users.app.test/auth/magic-link?guard=users#token=');

    $this->postJson('/users/auth/login/magic-link/consume', ['token' => tokenFromUrl($url)], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    expect($user->fresh()?->hasVerifiedEmail())->toBeTrue()
        ->and(OneTimeToken::query()->sole()->consumed_at)->not->toBeNull();
    Event::assertDispatched(MagicLinkRequested::class);
});

it('answers unknown and disabled addresses identically and sends nothing', function (callable $email): void {
    $this->postJson('/users/auth/login/magic-link', ['email' => $email()])
        ->assertStatus(202)
        ->assertExactJson(['status' => 'sent']);

    Notification::assertNothingSent();
    expect(OneTimeToken::query()->count())->toBe(0);
})->with([
    'unknown' => [fn (): string => 'ghost@example.com'],
    'disabled' => [fn (): string => User::factory()->disabled()->create()->email],
]);

it('only accepts the newest link, once', function (): void {
    $user = User::factory()->create();
    $first = requestLink($user);
    $second = requestLink($user);

    expect(fn () => Authentication::guard('users')->consumeMagicLink($first, sessionContext()))->toThrow(InvalidOneTimeToken::class)
        ->and(Authentication::guard('users')->consumeMagicLink($second, sessionContext())->isAuthenticated())->toBeTrue()
        ->and(fn () => Authentication::guard('users')->consumeMagicLink($second, sessionContext()))->toThrow(InvalidOneTimeToken::class);
});

it('never accepts a link under another guard', function (): void {
    $user = User::factory()->create();
    Client::factory()->create(['id' => $user->getKey(), 'email' => $user->email]);

    $token = requestLink($user);

    expect(fn () => Authentication::guard('clients')->consumeMagicLink($token, sessionContext()))->toThrow(InvalidOneTimeToken::class)
        ->and(Authentication::guard('users')->consumeMagicLink($token, sessionContext())->isAuthenticated())->toBeTrue();
});

it('dies with an address change', function (): void {
    $user = User::factory()->create();
    $token = requestLink($user);

    $user->forceFill(['email' => 'new@example.com'])->save();

    Authentication::guard('users')->consumeMagicLink($token, sessionContext());
})->throws(InvalidOneTimeToken::class);

it('binds to the requesting device when same_device is on, without burning the link', function (): void {
    $this->configureGuard('users', ['magic_link.same_device' => true]);
    $user = User::factory()->create();

    Authentication::guard('users')->requestMagicLink($user->email, sessionContext('Laptop'));
    $token = tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url);

    expect(fn () => Authentication::guard('users')->consumeMagicLink($token, sessionContext('Phone')))->toThrow(InvalidOneTimeToken::class)
        ->and(Authentication::guard('users')->consumeMagicLink($token, sessionContext('Laptop'))->isAuthenticated())->toBeTrue();
});

it('still requires the second factor after a magic link unless the guard opts out', function (): void {
    $user = User::factory()->create();
    enableTotp($user);

    expect(Authentication::guard('users')->consumeMagicLink(requestLink($user), sessionContext())->requiresChallenge())->toBeTrue();

    $this->configureGuard('users', ['two_factor.after_email_login' => false]);
    expect(Authentication::guard('users')->consumeMagicLink(requestLink($user), sessionContext())->isAuthenticated())->toBeTrue();
});

it('expires exactly at its ttl', function (): void {
    $user = User::factory()->create();
    $token = requestLink($user);

    $this->travel(900)->seconds();

    Authentication::guard('users')->consumeMagicLink($token, sessionContext());
})->throws(InvalidOneTimeToken::class);

it('is absent when magic links are off', function (): void {
    $this->configureGuard('users', ['login.magic_link' => false]);

    expect(fn () => Authentication::guard('users')->requestMagicLink('x@example.com', sessionContext()))->toThrow(LoginMethodDisabled::class)
        ->and(fn () => Authentication::guard('users')->consumeMagicLink('x', sessionContext()))->toThrow(LoginMethodDisabled::class);
});

it('renders an unknown token as a uniform 422', function (): void {
    $this->postJson('/users/auth/login/magic-link/consume', ['token' => 'nope'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'invalid_token')
        ->assertJsonPath('errors.token.0', __('authentication::messages.errors.invalid_token'));
});

it('mails an address-routed link to accounts without the Notifiable trait', function (): void {
    $this->configureGuard('clients', ['model' => PlainAccount::class]);
    $account = PlainAccount::query()->create(['email' => 'plain@example.com']);

    Authentication::guard('clients')->requestMagicLink('plain@example.com', sessionContext());

    Notification::assertSentTo(new AnonymousNotifiable, MagicLinkNotification::class, fn ($notification, $channels, $notifiable): bool => $notifiable->routes['mail'] === 'plain@example.com');
    expect($account->exists)->toBeTrue();
});
