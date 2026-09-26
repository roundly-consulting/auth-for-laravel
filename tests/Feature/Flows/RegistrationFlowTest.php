<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Events\AccountRegistered;
use RoundlyConsulting\Auth\Exceptions\InvitationRequired;
use RoundlyConsulting\Auth\Exceptions\RegistrationClosed;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\AccountExistsNotification;
use RoundlyConsulting\Auth\Notifications\VerifyEmailNotification;
use RoundlyConsulting\Auth\Support\RegistrationValidator;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\Fixtures\Support\NestedProfileRules;
use RoundlyConsulting\Auth\Tests\Fixtures\Support\ProfileRules;

beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['registration.rules' => ProfileRules::class, 'locale.supported' => ['en', 'sk']]);
});

function registration(array $overrides = []): array
{
    return [
        'email' => 'New.User@Example.com',
        'password' => 'a-long-enough-passphrase',
        'attributes' => ['name' => 'New User', 'is_admin' => true],
        ...$overrides,
    ];
}

it('registers, sends the verification mail and signs in', function (): void {
    Event::fake([AccountRegistered::class]);

    $this->postJson('/users/auth/register', registration(), ['User-Agent' => 'PestBrowser/1.0', 'Accept-Language' => 'sk'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    $user = User::query()->sole();

    expect($user->email)->toBe('new.user@example.com')
        ->and($user->name)->toBe('New User')
        ->and($user->getAttribute('is_admin'))->toBeNull()
        ->and($user->accountLocale())->toBe('sk')
        ->and($user->hasVerifiedEmail())->toBeFalse()
        ->and($user->getAttribute('password_changed_at'))->not->toBeNull();

    Notification::assertSentTo($user, VerifyEmailNotification::class);
    Event::assertDispatched(AccountRegistered::class);
});

it('validates the host fields and the password policy', function (): void {
    $this->postJson('/users/auth/register', registration(['password' => 'short', 'attributes' => []]))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['password', 'attributes.name']);
});

it('refuses closed and invite-only registration', function (): void {
    $this->configureGuard('users', ['registration.mode' => 'closed']);
    expect(fn () => Authentication::guard('users')->register(new RegistrationData('a@b.test', 'a-long-enough-passphrase', sessionContext())))->toThrow(RegistrationClosed::class);

    $this->configureGuard('users', ['registration.mode' => 'invite_only']);
    expect(fn () => Authentication::guard('users')->register(new RegistrationData('a@b.test', 'a-long-enough-passphrase', sessionContext())))->toThrow(InvitationRequired::class);

    $this->postJson('/clients/auth/register', registration())->assertNotFound();
});

it('answers "email taken" when tokens would be issued immediately', function (): void {
    User::factory()->create(['email' => 'new.user@example.com']);

    $this->postJson('/users/auth/register', registration())
        ->assertStatus(422)
        ->assertJsonValidationErrors('email');
});

it('answers identically for a new and an existing address in the enumeration-safe modes', function (string $mode, bool $loginAfter, string $status): void {
    $this->configureGuard('users', ['verification.mode' => $mode, 'registration.login_after' => $loginAfter]);
    $existing = User::factory()->create(['email' => 'taken@example.com']);

    $new = $this->postJson('/users/auth/register', registration(['email' => 'fresh@example.com']))->assertStatus(202)->json();
    $taken = $this->postJson('/users/auth/register', registration(['email' => 'taken@example.com']))->assertStatus(202)->json();

    expect($new)->toBe($taken)->and($new)->toBe(['status' => $status]);
    Notification::assertSentOnDemand(AccountExistsNotification::class, fn ($n, $c, $notifiable): bool => $notifiable->routes['mail'] === 'taken@example.com');
    expect($existing->exists)->toBeTrue();
})->with([
    'required for login' => ['required_for_login', true, 'verification_required'],
    'no login after' => ['optional', false, 'accepted'],
]);

it('returns a challenge when the new account must enrol a factor, or asks to verify first', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'challenge.enrolment_requires_verified_email' => false]);

    $this->postJson('/users/auth/register', registration(), ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'challenge')
        ->assertJsonPath('remaining.0.step', 'enrol_two_factor');

    $this->configureGuard('users', ['challenge.enrolment_requires_verified_email' => true]);

    $this->postJson('/users/auth/register', registration(['email' => 'second@example.com']))
        ->assertStatus(202)
        ->assertExactJson(['status' => 'verification_required']);
});

it('registers without a password when password login is off', function (): void {
    $this->configureGuard('users', ['login.password' => false]);

    $result = Authentication::guard('users')->register(new RegistrationData('nopass@example.com', null, sessionContext(), ['name' => 'X']));

    expect($result->status)->toBe(RegistrationStatus::Authenticated)
        ->and(User::query()->sole()->hasPassword())->toBeFalse()
        ->and(claimsOf($result->login->tokens)->authMethods())->toBe([]);
});

it('throttles registrations per ip', function (): void {
    $this->configureGuard('users', ['throttle.registration.max' => 1]);

    $this->postJson('/users/auth/register', registration())->assertOk();
    $this->postJson('/users/auth/register', registration(['email' => 'other@example.com']))->assertStatus(429);
});

it('keeps host attributes ruled by dotted and wildcard keys, and nothing unruled', function (): void {
    $this->configureGuard('users', ['registration.rules' => NestedProfileRules::class]);

    $clean = app(RegistrationValidator::class)->validate(
        app(GuardRegistry::class)->get('users'),
        'n@example.com',
        'a-long-enough-passphrase',
        ['name' => 'N', 'profile' => ['city' => 'Bratislava', 'is_admin' => true], 'tags' => ['a', 'b'], 'is_admin' => true],
    );

    expect($clean)->toBe(['name' => 'N', 'profile' => ['city' => 'Bratislava'], 'tags' => ['a', 'b']]);
});

it('treats the composed and decomposed spellings of an address as one account', function (): void {
    $this->configureGuard('users', ['registration.login_after' => false]);
    User::factory()->create(['email' => "jos\u{00E9}@example.com"]);

    $this->postJson('/users/auth/register', ['email' => "jose\u{0301}@example.com", 'password' => 'a-long-enough-passphrase', 'attributes' => ['name' => 'Jose']])->assertStatus(202);

    expect(User::query()->count())->toBe(1)
        ->and(Authentication::guard('users')->attempt(new PasswordCredentials("jose\u{0301}@example.com", 'correct-horse-battery'), sessionContext())->isAuthenticated())->toBeTrue();
});
