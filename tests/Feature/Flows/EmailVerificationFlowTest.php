<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Auth\Actions\Email\SendEmailVerification;
use RoundlyConsulting\Auth\Events\EmailVerified;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Notifications\VerifyEmailNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

it('verifies with the emailed link', function (): void {
    Event::fake([EmailVerified::class]);
    $user = User::factory()->unverified()->create();

    $this->postJson('/users/auth/email/verification', [], bearer(issuePair($user)))->assertStatus(202);
    $token = tokenFromUrl(sentNotification($user, VerifyEmailNotification::class)->data->url);

    $this->postJson('/users/auth/email/verify', ['token' => $token])->assertOk()->assertExactJson(['status' => 'verified']);

    expect($user->fresh()?->hasVerifiedEmail())->toBeTrue();
    Event::assertDispatched(EmailVerified::class);
});

it('verifies with a code on the code channel', function (): void {
    $this->configureGuard('users', ['verification.channel' => 'code']);
    $user = User::factory()->unverified()->create();

    app(SendEmailVerification::class)->execute('users', $user);
    $code = (string) sentNotification($user, VerifyEmailNotification::class)->data->code;

    $this->postJson('/users/auth/email/verify', ['token' => '000000', 'email' => $user->email])->assertStatus(422)->assertJsonMissingPath('attempts_left');
    $this->postJson('/users/auth/email/verify', ['token' => $code])->assertStatus(422);
    $this->postJson('/users/auth/email/verify', ['token' => $code, 'email' => $user->email])->assertOk();
});

it('refuses a link sent before an email change', function (): void {
    $user = User::factory()->unverified()->create();
    app(SendEmailVerification::class)->execute('users', $user);
    $token = tokenFromUrl(sentNotification($user, VerifyEmailNotification::class)->data->url);

    $user->forceFill(['email' => 'changed@example.com'])->save();

    $this->postJson('/users/auth/email/verify', ['token' => $token])->assertStatus(422)->assertJsonPath('code', 'invalid_token');
});

it('resends to real unverified accounts only, with a per-account cooldown', function (): void {
    $user = User::factory()->unverified()->create();
    $verified = User::factory()->create();

    $this->postJson('/users/auth/email/verification/resend', ['email' => $user->email])->assertStatus(202);
    $this->postJson('/users/auth/email/verification/resend', ['email' => $user->email])->assertStatus(202);
    $this->postJson('/users/auth/email/verification/resend', ['email' => $verified->email])->assertStatus(202);
    $this->postJson('/users/auth/email/verification/resend', ['email' => 'ghost@example.com'])->assertStatus(202);

    Notification::assertSentToTimes($user, VerifyEmailNotification::class, 1);
    Notification::assertNotSentTo($verified, VerifyEmailNotification::class);
});

it('applies the same cooldown and address budget to the signed-in send', function (): void {
    $user = User::factory()->unverified()->create();
    $headers = bearer(issuePair($user));
    CarbonImmutable::setTestNow(CarbonImmutable::now());

    foreach (range(1, 3) as $attempt) {
        $this->postJson('/users/auth/email/verification', [], $headers)->assertStatus(202);
    }

    Notification::assertSentToTimes($user, VerifyEmailNotification::class, 1);

    // verification.resend_decay = 60 s.
    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(61));
    $this->postJson('/users/auth/email/verification', [], $headers)->assertStatus(202);
    Notification::assertSentToTimes($user, VerifyEmailNotification::class, 2);

    // email_request_account = 10 per hour and address.
    foreach (range(5, 10) as $attempt) {
        $this->postJson('/users/auth/email/verification', [], $headers)->assertStatus(202);
    }

    $this->postJson('/users/auth/email/verification', [], $headers)->assertStatus(429)->assertJsonPath('code', 'too_many_attempts');
    CarbonImmutable::setTestNow();
});

it('does nothing for a verified account and is absent when verification is off', function (): void {
    $user = User::factory()->create();
    app(SendEmailVerification::class)->execute('users', $user);
    Notification::assertNothingSent();

    $this->configureGuard('users', ['verification.mode' => 'off']);
    expect(fn () => app(SendEmailVerification::class)->execute('users', $user))->toThrow(LoginMethodDisabled::class);
});

it('gates host routes on a verified address when required for actions', function (): void {
    Route::middleware(['auth:users', 'authentication.verified:users', 'authentication.active:users'])->get('/_verified', fn () => 'ok');
    $unverified = User::factory()->unverified()->create();

    $this->get('/_verified', bearer(issuePair($unverified)))->assertOk();

    $this->configureGuard('users', ['verification.mode' => 'required_for_actions']);
    $this->get('/_verified', bearer(issuePair($unverified)))->assertForbidden()->assertJsonPath('code', 'email_not_verified');
    $this->get('/_verified', bearer(issuePair(User::factory()->create())))->assertOk();
});
