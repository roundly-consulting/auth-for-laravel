<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Events\LoginActivityRecorded;
use RoundlyConsulting\Auth\Events\LoginFailed;
use RoundlyConsulting\Auth\Events\LoginSucceeded;
use RoundlyConsulting\Auth\Events\PasswordRehashed;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('logs in with email and password over http', function (): void {
    $user = User::factory()->create(['email' => 'ada@example.com']);

    $response = $this->postJson('/users/auth/login', ['identifier' => ' ADA@example.com ', 'password' => 'correct-horse-battery', 'device_name' => 'Laptop'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJsonPath('status', 'authenticated')
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonStructure(['access_token', 'expires_in', 'expires_at', 'refresh_token', 'refresh_expires_at', 'session_id']);

    $this->getJson('/users/auth/me', ['Authorization' => 'Bearer '.$response->json('access_token')])->assertOk();

    expect($user->fresh()?->getAttribute('last_login_at'))->not->toBeNull()
        ->and(LoginActivity::query()->where('outcome', 'succeeded')->sole()->identifier)->toBe('ADA@example.com')
        ->and(Authentication::guard('users')->sessions($user)->sole()->deviceName)->toBe('Laptop');
});

it('answers a wrong password, an unknown account and a passwordless account identically', function (callable $identifier): void {
    $this->postJson('/users/auth/login', ['identifier' => $identifier(), 'password' => 'wrong-password'])
        ->assertStatus(422)
        ->assertExactJson([
            'message' => __('authentication::messages.errors.invalid_credentials'),
            'code' => 'invalid_credentials',
            'errors' => ['identifier' => [__('authentication::messages.errors.invalid_credentials')]],
        ]);
})->with([
    'wrong password' => [fn (): string => User::factory()->create()->email],
    'unknown account' => [fn (): string => 'nobody@example.com'],
    'passwordless account' => [fn (): string => User::factory()->passwordless()->create()->email],
]);

it('reveals account state only after a verified first factor', function (): void {
    $user = User::factory()->disabled()->create();

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'wrong-password'])->assertStatus(422)->assertJsonPath('code', 'invalid_credentials');
    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'])->assertForbidden()->assertJsonPath('code', 'account_disabled');

    $this->configureGuard('users', ['login.reveal_account_state' => false]);
    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'])->assertStatus(422)->assertJsonPath('code', 'invalid_credentials');
});

it('refuses an unverified account when verification is required for login', function (): void {
    $this->configureGuard('users', ['verification.mode' => 'required_for_login']);
    $user = User::factory()->unverified()->create();

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'])
        ->assertForbidden()
        ->assertJsonPath('code', 'email_not_verified');

    expect(LoginActivity::query()->where('outcome', ActivityOutcome::Unverified->value)->count())->toBe(1);
});

it('is absent when password login is off', function (): void {
    $this->postJson('/clients/auth/login', ['identifier' => 'x@example.com', 'password' => 'whatever'])->assertNotFound();

    $this->configureGuard('users', ['login.password' => false, 'login.magic_link' => true]);
    Authentication::guard('users')->attempt(new PasswordCredentials('x@example.com', 'whatever'), sessionContext());
})->throws(LoginMethodDisabled::class);

it('validates the payload', function (): void {
    $this->postJson('/users/auth/login', ['identifier' => '', 'password' => str_repeat('x', 1025)])
        ->assertStatus(422)
        ->assertJsonValidationErrors(['identifier', 'password']);
});

it('rehashes an outdated password quietly on login', function (): void {
    Event::fake([PasswordRehashed::class]);
    $user = User::factory()->create(['password' => Hash::make('correct-horse-battery', ['rounds' => 4])]);
    config()->set('hashing.bcrypt.rounds', 5);

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect(Hash::needsRehash((string) $user->fresh()?->getAttribute('password')))->toBeFalse()
        ->and($user->fresh()?->tokenVersion())->toBe(0);
    Event::assertDispatched(PasswordRehashed::class);
});

it('fills the account locale from the request on login', function (): void {
    $this->configureGuard('users', ['locale.supported' => ['en', 'sk']]);
    $user = User::factory()->create();

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'], ['Accept-Language' => 'sk-SK,sk;q=0.9'])->assertOk();

    expect($user->fresh()?->accountLocale())->toBe('sk');
});

it('runs the success tail in order', function (): void {
    $user = User::factory()->create();
    $order = [];

    Event::listen(TokensIssued::class, function () use (&$order): void {
        $order[] = 'tokens';
    });
    Event::listen(LoginActivityRecorded::class, function () use (&$order): void {
        $order[] = 'activity';
    });
    Event::listen(LoginSucceeded::class, function () use (&$order): void {
        $order[] = 'succeeded';
    });

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect($order)->toBe(['activity', 'succeeded', 'tokens']);
});

it('records every failed attempt with its reason', function (): void {
    Event::fake([LoginFailed::class]);
    $user = User::factory()->create();

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'nope-nope-nope'), sessionContext()))->toThrow(InvalidCredentials::class);

    $row = LoginActivity::query()->sole();

    expect($row->type)->toBe(ActivityType::PasswordLogin)
        ->and($row->outcome)->toBe(ActivityOutcome::FailedCredentials)
        ->and($row->account_id)->toBe($user->getKey())
        ->and($row->ip_address)->toBe('10.0.0.1');
    Event::assertDispatched(LoginFailed::class, fn (LoginFailed $event): bool => $event->account?->is($user) === true);
});

it('stores the identifier hashed or not at all when configured', function (string $storage, ?string $expected): void {
    $this->configureGuard('users', ['activity.store_identifier' => $storage]);

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials('Nobody@Example.com', 'x'), sessionContext()))->toThrow(InvalidCredentials::class);

    $stored = LoginActivity::query()->sole()->identifier;

    $expected === 'hash' ? expect($stored)->toHaveLength(64)->not->toContain('@') : expect($stored)->toBe($expected);
})->with([
    'plain' => ['plain', 'Nobody@Example.com'],
    'hash' => ['hash', 'hash'],
    'none' => ['none', null],
]);

it('hashes the composed and decomposed spellings of an identifier alike', function (): void {
    $this->configureGuard('users', ['activity.store_identifier' => 'hash']);

    foreach (["Jos\u{00E9}@example.com", " jose\u{0301}@example.com "] as $spelling) {
        expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($spelling, 'x'), sessionContext()))->toThrow(InvalidCredentials::class);
    }

    expect(LoginActivity::query()->pluck('identifier')->unique()->all())->toHaveCount(1);
});

it('writes no activity when the log is off', function (): void {
    $this->configureGuard('users', ['activity.enabled' => false]);

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials('nobody@example.com', 'x'), sessionContext()))->toThrow(InvalidCredentials::class)
        ->and(LoginActivity::query()->count())->toBe(0);
});

it('stamps the login time in the app timezone', function (): void {
    CarbonImmutable::setTestNow('2026-09-26 12:00:00');
    $user = User::factory()->create();

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect($user->fresh()?->getAttribute('last_login_at')?->toDateTimeString())->toBe('2026-09-26 12:00:00');
    CarbonImmutable::setTestNow();
});
