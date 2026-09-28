<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Events\LoggedOut;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Exceptions\SessionNotFound;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\Contexts\ChallengesContext;
use RoundlyConsulting\Auth\Guards\Contexts\EmailContext;
use RoundlyConsulting\Auth\Guards\Contexts\InvitationsContext;
use RoundlyConsulting\Auth\Guards\Contexts\PasskeysContext;
use RoundlyConsulting\Auth\Guards\Contexts\PasswordsContext;
use RoundlyConsulting\Auth\Guards\Contexts\ReauthenticationContext;
use RoundlyConsulting\Auth\Guards\Contexts\TwoFactorContext;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Every per-guard method on the facade root runs on `authentication.default`:
 * `Authentication::twoFactor()->status($user)` ≡ `Authentication::guard()->twoFactor()->status($user)`.
 */
it('answers the flagship call on the default guard', function (): void {
    $user = User::factory()->create();
    enableTotp($user);

    $status = Authentication::twoFactor()->status($user);

    expect($status->enabled)->toBeTrue()
        ->and($status->recoveryCodesRemaining)->toBe(3)
        ->and($status)->toEqual(Authentication::guard('users')->twoFactor()->status($user));
});

it('follows authentication.default, not a hard-coded guard', function (): void {
    config()->set('authentication.default', 'clients');
    $client = Client::factory()->create();

    expect(Authentication::name())->toBe('clients')
        ->and(Authentication::config()->name())->toBe('clients')
        ->and(Authentication::accounts()->morphClass())->toBe($client->getMorphClass())
        ->and(Authentication::sessions($client))->toBeEmpty()
        ->and(fn () => Authentication::sessions(User::factory()->create()))->toThrow(AuthenticationMisconfigured::class, 'belongs to another guard');
});

it('hands out every sub-area of the default guard', function (): void {
    expect(Authentication::twoFactor())->toBeInstanceOf(TwoFactorContext::class)
        ->and(Authentication::passkeys())->toBeInstanceOf(PasskeysContext::class)
        ->and(Authentication::passwords())->toBeInstanceOf(PasswordsContext::class)
        ->and(Authentication::email())->toBeInstanceOf(EmailContext::class)
        ->and(Authentication::invitations())->toBeInstanceOf(InvitationsContext::class)
        ->and(Authentication::reauthentication())->toBeInstanceOf(ReauthenticationContext::class)
        ->and(Authentication::challenges())->toBeInstanceOf(ChallengesContext::class);
});

it('serves the same API through the injected manager', function (): void {
    $user = User::factory()->create();
    $manager = app(AuthenticationManager::class);

    expect($manager)->toBe(Authentication::getFacadeRoot())
        ->and($manager->twoFactor()->status($user)->enabled)->toBeFalse()
        ->and($manager->guard('users')->passkeys()->all($user))->toBeEmpty()
        ->and($manager->lock($user, 60)->isFuture())->toBeTrue()
        ->and($user->fresh()?->isLocked())->toBeTrue();
});

it('logs in, refreshes and logs out on the default guard', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $context = sessionContext();

    $login = Authentication::attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), $context);
    $refreshed = Authentication::refresh((string) $login->tokens?->refreshToken, $context);

    Authentication::requestMagicLink($user->email, $context);
    $viaLink = Authentication::consumeMagicLink(tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url), $context);

    Authentication::requestEmailOtp($user->email, $context);
    $viaCode = Authentication::verifyEmailOtp($user->email, (string) sentNotification($user, EmailOtpNotification::class)->data->code, $context);

    expect($login->isAuthenticated())->toBeTrue()
        ->and($refreshed->sessionId)->toBe($login->tokens?->sessionId)
        ->and($viaLink->isAuthenticated())->toBeTrue()
        ->and($viaCode->isAuthenticated())->toBeTrue()
        ->and(Authentication::sessions($user))->toHaveCount(3)
        ->and(fn () => Authentication::consumeMagicLink('nope', $context))->toThrow(InvalidOneTimeToken::class)
        ->and(fn () => Authentication::verifyEmailOtp($user->email, '000000', $context))->toThrow(InvalidCode::class)
        ->and(fn () => Authentication::refresh('nope', $context))->toThrow(InvalidRefreshToken::class);
});

it('runs passkey login on the default guard', function (): void {
    $user = User::factory()->create();
    $authenticator = registerVirtualPasskey($user);

    $options = Authentication::passkeyLoginOptions(sessionContext());
    $result = Authentication::loginWithPasskey($authenticator->assert($options), sessionContext());

    expect($result->isAuthenticated())->toBeTrue();
});

it('registers on the default guard', function (): void {
    Notification::fake();

    $result = Authentication::register(new RegistrationData('new@example.com', 'a-long-enough-passphrase', sessionContext()));

    expect($result->status)->not->toBe(RegistrationStatus::VerificationRequired)
        ->and(User::query()->where('email', 'new@example.com')->exists())->toBeTrue();
});

it('issues and ends sessions on the default guard', function (): void {
    Event::fake([TokensIssued::class, LoggedOut::class]);
    $user = User::factory()->create();

    $first = Authentication::issueTokens($user, sessionContext(), LoginMethod::Host);
    $second = Authentication::issueTokens($user, sessionContext());
    $third = Authentication::issueTokens($user, sessionContext());
    $current = currentTokenOf($third);

    Authentication::logoutSession($user, $first->sessionId);
    expect(Authentication::logoutOthers($user, $current))->toBe(1);
    Authentication::logout($user, $current);

    expect(Authentication::sessions($user))->toBeEmpty()
        ->and(fn () => Authentication::logoutSession($user, $second->sessionId))->toThrow(SessionNotFound::class);

    Authentication::issueTokens($user, sessionContext());
    expect(Authentication::logoutEverywhere($user))->toBe(1)
        ->and(Authentication::invalidate($user, InvalidationReason::Security))->toBeNull();

    Event::assertDispatchedTimes(TokensIssued::class, 4);
    Event::assertDispatchedTimes(LoggedOut::class, 4);
});

it('manages the account on the default guard', function (): void {
    Notification::fake();
    $user = User::factory()->create();

    Authentication::disable($user, 'fraud');
    expect($user->fresh()?->isDisabled())->toBeTrue();

    Authentication::enable($user);
    Authentication::lock($user);
    expect($user->fresh()?->isLocked())->toBeTrue();

    Authentication::unlock($user);
    $updated = Authentication::updateLocale($user, new LocaleData('en', updatesTimezone: false));

    expect($user->fresh()?->isDisabled())->toBeFalse()
        ->and($user->fresh()?->isLocked())->toBeFalse()
        ->and($updated->accountLocale())->toBe('en');
});

it('pages the login activity of an account', function (): void {
    $user = User::factory()->create();
    LoginActivity::factory()->count(3)->create(['guard' => 'users', 'account_type' => $user->getMorphClass(), 'account_id' => $user->getKey()]);
    LoginActivity::factory()->create(['guard' => 'clients', 'account_type' => $user->getMorphClass(), 'account_id' => $user->getKey()]);

    $page = Authentication::activity($user, perPage: 2);

    expect($page->total())->toBe(3)
        ->and($page->items())->toHaveCount(2)
        ->and(Authentication::guard('users')->activity($user)->total())->toBe(3);
});

it('reads the session context and the current token from a request', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->getJson('/users/auth/me', bearer($pair))->assertOk();

    $request = Request::create('/', 'GET', ['device_name' => 'Laptop'], server: ['REMOTE_ADDR' => '10.1.2.3', 'HTTP_USER_AGENT' => 'Browser/2']);
    $context = Authentication::contextFrom($request);
    $token = Authentication::tokenFrom(request());

    expect($context->ipAddress)->toBe('10.1.2.3')
        ->and($context->deviceName)->toBe('Laptop')
        ->and($token->sessionId)->toBe($pair->sessionId);
});

it('prunes through the facade', function (): void {
    LoginActivity::factory()->create(['guard' => 'users', 'created_at' => now()->subDays(400)]);

    $report = Authentication::prune(days: 30);

    expect($report->activities)->toBe(1)
        ->and(LoginActivity::query()->count())->toBe(0);
});
