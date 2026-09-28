<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordResetData;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\ResetPasswordNotification;
use RoundlyConsulting\Auth\Rules\PasswordPolicy;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

it('sets a password from host code and ends every session', function (): void {
    Event::fake([PasswordChanged::class]);
    $user = User::factory()->create();
    $pair = issuePair($user);

    Authentication::guard('users')->passwords()->set($user, 'n3w-Passphrase!', InvalidationReason::Security);

    expect(Hash::check('n3w-Passphrase!', (string) $user->fresh()?->password))->toBeTrue();
    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    Event::assertDispatched(PasswordChanged::class);
});

it('refuses a weak password before writing it', function (): void {
    $user = User::factory()->create();

    expect(fn () => Authentication::passwords()->set($user, 'short'))->toThrow(ValidationException::class)
        ->and(Hash::check('correct-horse-battery', (string) $user->fresh()?->password))->toBeTrue();
});

it('changes the signed-in password and keeps the calling device', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $tokens = Authentication::passwords()->change($user, new ChangePasswordData('correct-horse-battery', 'a-brand-new-passphrase', currentTokenOf($pair), sessionContext()));

    expect($tokens)->not->toBeNull()
        ->and(Hash::check('a-brand-new-passphrase', (string) $user->fresh()?->password))->toBeTrue();
    $this->getJson('/users/auth/me', bearer($tokens))->assertOk();
});

it('resets a forgotten password through the mailed link', function (): void {
    $user = User::factory()->create();

    Authentication::passwords()->requestReset($user->email, sessionContext());
    $token = tokenFromUrl(sentNotification($user, ResetPasswordNotification::class)->data->url);

    expect(Authentication::passwords()->reset(new PasswordResetData($token, 'a-brand-new-passphrase', sessionContext())))->toBeNull()
        ->and(Hash::check('a-brand-new-passphrase', (string) $user->fresh()?->password))->toBeTrue();
});

it('offers the guard policy as a check and as a rule', function (): void {
    $user = User::factory()->create(['email' => 'ada.lovelace@example.com']);
    $passwords = Authentication::passwords();

    $passwords->validate('a-brand-new-passphrase');
    $passwords->validate('a-brand-new-passphrase', $user);

    expect(fn () => $passwords->validate('short'))->toThrow(ValidationException::class)
        ->and(fn () => $passwords->validate('ada.lovelace-rocks-2026', $user))->toThrow(ValidationException::class)
        ->and(fn () => $passwords->validate('ada.lovelace-rocks-2026', email: 'ada.lovelace@example.com'))->toThrow(ValidationException::class)
        ->and($passwords->rule())->toBeInstanceOf(PasswordPolicy::class)
        ->and(Validator::make(['password' => 'short'], ['password' => [$passwords->rule()]])->fails())->toBeTrue()
        ->and(Validator::make(['password' => 'a-brand-new-passphrase'], ['password' => [$passwords->rule('x@example.com')]])->passes())->toBeTrue();
});

it('keeps the action form for dependency-injection purists', function (): void {
    $user = User::factory()->create();

    app(SetPassword::class)->execute('users', $user, 'n3w-Passphrase!');

    expect(Hash::check('n3w-Passphrase!', (string) $user->fresh()?->password))->toBeTrue();
});
