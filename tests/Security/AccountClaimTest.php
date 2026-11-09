<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Events\AccountClaimed;
use RoundlyConsulting\Auth\Events\AccountTokensInvalidated;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Notifications\VerifyEmailNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

/**
 * Account pre-hijacking: someone registers the victim's address first, sets a password,
 * signs in and enrols factors; the owner later signs in with a magic link or an email code.
 * With `verification.secure_on_email_login` the owner's first email login takes the
 * account over; without it (today's default) the earlier credentials stand.
 */
beforeEach(function (): void {
    Notification::fake();
});

function claimByEmailLogin(User $user, string $how): LoginResult
{
    if ($how === 'magic link') {
        Authentication::guard('users')->requestMagicLink($user->email, sessionContext());

        return Authentication::guard('users')->consumeMagicLink(tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url), sessionContext());
    }

    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext());

    return Authentication::guard('users')->verifyEmailOtp($user->email, (string) sentNotification($user, EmailOtpNotification::class)->data->code, sessionContext());
}

/**
 * The squatter: an unverified account with a password, a live session, TOTP and a passkey.
 */
function preHijackedAccount(): User
{
    $user = User::factory()->unverified()->create();
    enableTotp($user);
    addPasskey($user);

    return $user;
}

dataset('email logins', ['magic link', 'email code']);

it('keeps the earlier credentials by default', function (string $how): void {
    $this->configureGuard('users', ['login.magic_link' => true, 'login.email_otp' => true, 'two_factor.after_email_login' => false]);
    $user = User::factory()->unverified()->create();
    $earlier = issuePair($user);

    expect(claimByEmailLogin($user, $how)->isAuthenticated())->toBeTrue();

    $fresh = $user->fresh();
    expect($fresh?->hasVerifiedEmail())->toBeTrue()
        ->and($fresh?->hasPassword())->toBeTrue();
    $this->getJson('/users/auth/me', bearer($earlier))->assertOk();
})->with('email logins');

it('discards everything set before the address was proven', function (string $how): void {
    Event::fake([AccountClaimed::class, AccountTokensInvalidated::class]);
    $this->configureGuard('users', ['login.magic_link' => true, 'login.email_otp' => true, 'verification.secure_on_email_login' => true]);
    $user = preHijackedAccount();
    $earlier = issuePair($user);
    Authentication::guard('users')->passwords()->requestReset($user->email, sessionContext());
    $pendingReset = OneTimeToken::query()->where('purpose', OneTimeTokenPurpose::PasswordReset->value)->sole();

    // The squatter's TOTP and passkey are gone too, so the owner is in without them.
    $result = claimByEmailLogin($user, $how);

    expect($result->isAuthenticated())->toBeTrue();

    $fresh = $user->fresh();
    expect($fresh?->hasVerifiedEmail())->toBeTrue()
        ->and($fresh?->hasPassword())->toBeFalse()
        ->and($fresh?->getAttribute('password'))->toBeNull()
        ->and($fresh?->getAttribute('password_changed_at'))->toBeNull()
        ->and($fresh?->hasTwoFactorEnabled())->toBeFalse()
        ->and($fresh?->getAttribute('two_factor_secret'))->toBeNull()
        ->and(Passkey::query()->count())->toBe(0)
        ->and($pendingReset->fresh()?->invalidated_at)->not->toBeNull()
        ->and(RefreshTokens::sessions($user)->all())->toHaveCount(1);

    $this->getJson('/users/auth/me', bearer($earlier))->assertUnauthorized();
    $this->postJson('/users/auth/refresh', ['refresh_token' => $earlier->refreshToken], ['User-Agent' => 'PestBrowser/1.0'])->assertStatus(401);
    $this->getJson('/users/auth/me', bearer($result->tokens))->assertOk();
    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))
        ->toThrow(InvalidCredentials::class);

    Event::assertDispatchedTimes(AccountClaimed::class, 1);
    Event::assertDispatched(AccountClaimed::class, fn (AccountClaimed $event): bool => $event->guard === 'users'
        && $event->account->is($user)
        && $event->method === ($how === 'magic link' ? LoginMethod::MagicLink : LoginMethod::EmailOtp)
        && $event->passwordRemoved
        && $event->twoFactorRemoved
        && $event->passkeysRemoved === 1
        && $event->sessionsRevoked === 1);
    Event::assertDispatched(AccountTokensInvalidated::class, fn (AccountTokensInvalidated $event): bool => $event->reason === InvalidationReason::Security);
})->with('email logins');

it('reports only what there was to remove', function (): void {
    Event::fake([AccountClaimed::class]);
    $this->configureGuard('users', ['login.magic_link' => true, 'verification.secure_on_email_login' => true, 'passkeys.mode' => 'off', 'login.passkey' => false]);
    $user = User::factory()->unverified()->passwordless()->create();
    addPasskey($user);

    expect(claimByEmailLogin($user, 'magic link')->isAuthenticated())->toBeTrue()
        // Passkeys are off: nothing can use the stored one, so it is left alone.
        ->and(Passkey::query()->count())->toBe(1);

    Event::assertDispatched(AccountClaimed::class, fn (AccountClaimed $event): bool => ! $event->passwordRemoved
        && ! $event->twoFactorRemoved
        && $event->passkeysRemoved === 0
        && $event->sessionsRevoked === 0);
});

it('removes a pending two-factor enrolment too', function (): void {
    $this->configureGuard('users', ['login.magic_link' => true, 'verification.secure_on_email_login' => true]);
    $user = User::factory()->unverified()->create();
    $user->forceFill(['two_factor_secret' => 'JBSWY3DPEHPK3PXP'])->save();

    claimByEmailLogin($user, 'magic link');

    expect($user->fresh()?->getAttribute('two_factor_secret'))->toBeNull();
});

it('leaves a verified account alone', function (string $how): void {
    Event::fake([AccountClaimed::class]);
    $this->configureGuard('users', ['login.magic_link' => true, 'login.email_otp' => true, 'two_factor.after_email_login' => false, 'verification.secure_on_email_login' => true]);
    $user = User::factory()->create();
    $earlier = issuePair($user);

    expect(claimByEmailLogin($user, $how)->isAuthenticated())->toBeTrue()
        ->and($user->fresh()?->hasPassword())->toBeTrue();

    $this->getJson('/users/auth/me', bearer($earlier))->assertOk();
    Event::assertNotDispatched(AccountClaimed::class);
})->with('email logins');

it('does nothing while email logins leave the address unverified, and says so', function (): void {
    Event::fake([AccountClaimed::class]);
    $this->configureGuard('users', ['login.magic_link' => true, 'verification.secure_on_email_login' => true, 'verification.verify_on_email_login' => false]);
    $user = User::factory()->unverified()->create();

    claimByEmailLogin($user, 'magic link');

    expect($user->fresh()?->hasPassword())->toBeTrue()
        ->and($user->fresh()?->hasVerifiedEmail())->toBeFalse();
    Event::assertNotDispatched(AccountClaimed::class);

    $this->artisan('authentication:check', ['guard' => 'users'])
        ->expectsOutputToContain('secure_on_email_login never applies')
        ->assertSuccessful();
});

it('never runs on a password login or a verification link', function (): void {
    Event::fake([AccountClaimed::class]);
    $this->configureGuard('users', ['verification.secure_on_email_login' => true]);
    $user = User::factory()->unverified()->create();

    // The registrant's own path: password, then the link mailed to the address.
    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());
    Authentication::guard('users')->email()->sendVerification($user, sessionContext());
    $token = tokenFromUrl(sentNotification($user, VerifyEmailNotification::class)->data->url);
    Authentication::guard('users')->email()->verify($token, null, sessionContext());

    expect($user->fresh()?->hasVerifiedEmail())->toBeTrue()
        ->and($user->fresh()?->hasPassword())->toBeTrue();
    Event::assertNotDispatched(AccountClaimed::class);
});

it('stores an empty password where the column is NOT NULL', function (): void {
    // Laravel's stock users table, as the documented install leaves it.
    Schema::drop('users');
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name')->nullable();
        $table->string('email')->unique();
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password');
        $table->rememberToken();
        $table->timestamps();
        $table->softDeletes();
        $table->authenticationColumns();
        $table->twoFactorColumns();
        $table->passkeyUserHandle();
    });
    $this->configureGuard('users', ['login.magic_link' => true, 'verification.secure_on_email_login' => true]);
    $user = User::factory()->unverified()->create();

    expect(claimByEmailLogin($user, 'magic link')->isAuthenticated())->toBeTrue()
        ->and($user->fresh()?->getAttribute('password'))->toBe('')
        ->and($user->fresh()?->hasPassword())->toBeFalse();
    // An empty guess never matches the empty value.
    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, ''), sessionContext()))
        ->toThrow(InvalidCredentials::class);
    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))
        ->toThrow(InvalidCredentials::class);
});
