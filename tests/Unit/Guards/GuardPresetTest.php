<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Exceptions\EmailNotVerified;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardPreset;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * The hardened preset: the exact values the docs list, the guard's own settings merged
 * on top, and a guard built from it behaving accordingly.
 */
it('holds exactly the documented values', function (): void {
    expect(GuardPreset::hardened())->toBe([
        'registration' => ['uniform_response' => true],
        'verification' => ['mode' => 'required_for_login', 'verify_on_email_login' => true, 'secure_on_email_login' => true],
        'lockout' => ['enabled' => true],
    ]);
});

it('merges the guard\'s own settings over the preset, replacing lists', function (): void {
    $settings = GuardPreset::hardened([
        'model' => User::class,
        'verification' => ['mode' => 'optional'],
        'lockout' => ['threshold' => 5],
        'identifier' => ['columns' => ['username']],
    ]);

    expect($settings['model'])->toBe(User::class)
        ->and($settings['verification'])->toBe(['mode' => 'optional', 'verify_on_email_login' => true, 'secure_on_email_login' => true])
        ->and($settings['lockout'])->toBe(['enabled' => true, 'threshold' => 5])
        ->and($settings['identifier'])->toBe(['columns' => ['username']]);
});

it('makes a guard that refuses unverified sign-in and never reveals a taken address', function (): void {
    Notification::fake();
    $own = config('authentication.guards.users');
    config()->set('authentication.guards.users', GuardPreset::hardened(is_array($own) ? $own : []));
    app(GuardRegistry::class)->flush();

    $guard = Authentication::guard('users')->config();
    expect($guard->registrationAnswersUniformly())->toBeTrue()
        ->and($guard->verificationMode())->toBe(EmailVerificationMode::RequiredForLogin)
        ->and($guard->securesAccountOnEmailLogin())->toBeTrue()
        ->and($guard->lockoutEnabled())->toBeTrue();

    $unverified = User::factory()->unverified()->create();
    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($unverified->email, 'correct-horse-battery'), sessionContext()))
        ->toThrow(EmailNotVerified::class);

    $taken = Authentication::guard('users')->register(new RegistrationData($unverified->email, 'a-long-enough-passphrase', sessionContext()));
    $free = Authentication::guard('users')->register(new RegistrationData('free@example.com', 'a-long-enough-passphrase', sessionContext()));
    expect($taken->status)->toBe(RegistrationStatus::VerificationRequired)
        ->and($free->status)->toBe($taken->status);

    $this->artisan('authentication:check', ['guard' => 'users'])->assertSuccessful();
});
