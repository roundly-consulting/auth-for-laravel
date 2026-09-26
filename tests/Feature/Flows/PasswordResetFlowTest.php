<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Passwords\ChangePassword;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\BreachedPasswordCheckFailed;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Events\PasswordReset;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\PasswordChangedNotification;
use RoundlyConsulting\Auth\Notifications\ResetPasswordNotification;
use RoundlyConsulting\Auth\Support\NotPwnedPasswordChecker;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;

beforeEach(function (): void {
    Notification::fake();
});

function resetToken(User $user): string
{
    test()->postJson('/users/auth/password/forgot', ['email' => $user->email])->assertStatus(202)->assertExactJson(['status' => 'sent']);

    return tokenFromUrl(sentNotification($user, ResetPasswordNotification::class)->data->url);
}

it('resets a password through the emailed link and ends every session', function (): void {
    Event::fake([PasswordReset::class]);
    $user = User::factory()->unverified()->create(['locked_until' => now()->addHour()]);
    $pair = issuePair($user);

    $this->postJson('/users/auth/password/reset', ['token' => resetToken($user), 'password' => 'a-brand-new-passphrase'])
        ->assertOk()
        ->assertExactJson(['status' => 'reset']);

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    expect($user->fresh()?->hasVerifiedEmail())->toBeTrue()
        ->and($user->fresh()?->isLocked())->toBeFalse();
    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'a-brand-new-passphrase'])->assertOk();
    Event::assertDispatched(PasswordReset::class);
    Notification::assertSentTo($user, PasswordChangedNotification::class);
});

it('answers unknown addresses identically and sends nothing', function (): void {
    $this->postJson('/users/auth/password/forgot', ['email' => 'ghost@example.com'])->assertStatus(202)->assertExactJson(['status' => 'sent']);

    Notification::assertNothingSent();
});

it('validates the new password before consuming the link', function (): void {
    $user = User::factory()->create();
    $token = resetToken($user);

    $this->postJson('/users/auth/password/reset', ['token' => $token, 'password' => 'short'])->assertStatus(422)->assertJsonValidationErrors('password');

    expect(OneTimeToken::query()->sole()->consumed_at)->toBeNull();
    $this->postJson('/users/auth/password/reset', ['token' => $token, 'password' => 'a-brand-new-passphrase'])->assertOk();
    $this->postJson('/users/auth/password/reset', ['token' => $token, 'password' => 'a-brand-new-passphrase'])->assertStatus(422)->assertJsonPath('code', 'invalid_token');
});

it('signs in after a reset when configured — always through the second factor', function (): void {
    $this->configureGuard('users', ['passwords.reset.login_after' => true, 'two_factor.after_email_login' => false]);
    $user = User::factory()->create();

    $this->postJson('/users/auth/password/reset', ['token' => resetToken($user), 'password' => 'a-brand-new-passphrase'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    $totpUser = User::factory()->create();
    enableTotp($totpUser);

    $this->postJson('/users/auth/password/reset', ['token' => resetToken($totpUser), 'password' => 'a-brand-new-passphrase'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'challenge');
});

it('changes the password with the current one and returns the re-issued pair', function (): void {
    Event::fake([PasswordChanged::class]);
    $user = User::factory()->create();
    $pair = issuePair($user);
    $other = issuePair($user);

    $response = $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'a-brand-new-passphrase'], bearer($pair))
        ->assertOk()
        ->assertJsonPath('status', 'changed')
        ->assertJsonPath('tokens.status', 'authenticated');

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    $this->getJson('/users/auth/me', bearer($other))->assertUnauthorized();
    $this->getJson('/users/auth/me', ['Authorization' => 'Bearer '.$response->json('tokens.access_token')])->assertOk();
    Event::assertDispatched(PasswordChanged::class);
});

it('refuses a wrong current password and a reused one', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->putJson('/users/auth/password', ['current_password' => 'nope', 'password' => 'a-brand-new-passphrase'], bearer($pair))->assertStatus(422)->assertJsonValidationErrors('current_password');
    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'correct-horse-battery'], bearer($pair))->assertStatus(422)->assertJsonValidationErrors('password');
});

it('lets a passwordless account set one after a recent authentication', function (): void {
    $user = User::factory()->passwordless()->create();
    $pair = issuePair($user);

    $tokens = app(ChangePassword::class)->execute('users', $user, new ChangePasswordData(null, 'a-brand-new-passphrase', CurrentToken::fromClaims(claimsOf($pair)), sessionContext()));

    expect($tokens)->not->toBeNull()->and($user->fresh()?->hasPassword())->toBeTrue();
});

it('sets a password from host code', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    app(SetPassword::class)->execute('users', $user, 'an-admin-chosen-passphrase', InvalidationReason::Security);

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    Notification::assertSentTo($user, PasswordChangedNotification::class);
});

it('enforces the policy: bytes under bcrypt, identifier, composition', function (): void {
    $this->configureGuard('users', ['passwords.policy.numbers' => true]);
    $user = User::factory()->create(['email' => 'margaret@example.com']);
    $pair = issuePair($user);

    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => str_repeat('é', 40).'1'], bearer($pair))
        ->assertStatus(422)->assertJsonValidationErrors('password');
    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'my-name-is-margaret-1'], bearer($pair))
        ->assertStatus(422)->assertJsonValidationErrors('password');
    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'no-digits-in-this-one'], bearer($pair))
        ->assertStatus(422)->assertJsonValidationErrors('password');
});

it('checks breached passwords with a padded k-anonymity query', function (): void {
    $this->configureGuard('users', ['passwords.policy.uncompromised.enabled' => true]);
    $hash = strtoupper((new Digest(HashAlgorithm::Sha1))->hex('a-leaked-passphrase'));
    Http::fake([NotPwnedPasswordChecker::ENDPOINT.'*' => Http::response(substr($hash, 5).":42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0")]);
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'a-leaked-passphrase'], bearer($pair))
        ->assertStatus(422)->assertJsonValidationErrors('password');

    Http::assertSent(fn ($request): bool => $request->url() === NotPwnedPasswordChecker::ENDPOINT.substr($hash, 0, 5)
        && $request->hasHeader('Add-Padding', 'true')
        && ! str_contains($request->url(), substr($hash, 5)));

    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'a-fresh-unique-passphrase'], bearer($pair))->assertOk();
});

it('respects the breach threshold', function (): void {
    $this->configureGuard('users', ['passwords.policy.uncompromised.enabled' => true, 'passwords.policy.uncompromised.threshold' => 100]);
    $hash = strtoupper((new Digest(HashAlgorithm::Sha1))->hex('a-rarely-leaked-phrase'));
    Http::fake([NotPwnedPasswordChecker::ENDPOINT.'*' => Http::response(substr($hash, 5).':3')]);

    expect(app(NotPwnedPasswordChecker::class)->isBreached('a-rarely-leaked-phrase', guardConfig(['passwords' => ['policy' => ['uncompromised' => ['threshold' => 100]]]])))->toBeFalse();
});

it('fails open by default and closed when configured when the service is down', function (): void {
    Event::fake([BreachedPasswordCheckFailed::class]);
    Http::fake([NotPwnedPasswordChecker::ENDPOINT.'*' => Http::response('', 503)]);
    $this->configureGuard('users', ['passwords.policy.uncompromised.enabled' => true, 'invalidation.password_changed' => 'none']);
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'a-fresh-unique-passphrase'], bearer($pair))->assertOk();
    Event::assertDispatched(BreachedPasswordCheckFailed::class);

    $this->configureGuard('users', ['passwords.policy.uncompromised.fail_closed' => true]);
    $this->putJson('/users/auth/password', ['current_password' => 'a-fresh-unique-passphrase', 'password' => 'yet-another-passphrase'], bearer($pair))
        ->assertStatus(422)->assertJsonValidationErrors('password');
});
