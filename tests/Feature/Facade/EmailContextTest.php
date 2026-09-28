<?php

declare(strict_types=1);

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\EmailChangeData;
use RoundlyConsulting\Auth\Events\EmailChanged;
use RoundlyConsulting\Auth\Events\EmailVerified;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\ConfirmEmailChangeNotification;
use RoundlyConsulting\Auth\Notifications\VerifyEmailNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

it('sends a verification link from host code and verifies with it', function (): void {
    Event::fake([EmailVerified::class]);
    $user = User::factory()->unverified()->create();
    $email = Authentication::guard('users')->email();

    $email->sendVerification($user);
    $token = tokenFromUrl(sentNotification($user, VerifyEmailNotification::class)->data->url);

    expect($email->verify($token, null, sessionContext())->getKey())->toBe($user->getKey())
        ->and($user->fresh()?->hasVerifiedEmail())->toBeTrue();
    Event::assertDispatched(EmailVerified::class);

    // A verified account gets nothing more.
    $email->sendVerification($user->fresh() ?? $user, sessionContext());
    Notification::assertSentToTimes($user, VerifyEmailNotification::class, 1);
});

it('applies the cooldown to signed-in and guest resends', function (): void {
    $user = User::factory()->unverified()->create();

    Authentication::email()->requestVerification($user, sessionContext());
    Authentication::email()->requestVerification($user, sessionContext());
    Authentication::email()->resendVerification($user->email, sessionContext());
    Authentication::email()->resendVerification('ghost@example.com', sessionContext());

    Notification::assertSentToTimes($user, VerifyEmailNotification::class, 1);
});

it('changes an email once the new address confirms', function (): void {
    Event::fake([EmailChanged::class]);
    $user = User::factory()->create(['email' => 'old@example.com']);

    Authentication::email()->requestChange($user, new EmailChangeData('new@example.com', sessionContext()));
    expect($user->fresh()?->email)->toBe('old@example.com');

    $url = null;
    Notification::assertSentOnDemand(ConfirmEmailChangeNotification::class, function (ConfirmEmailChangeNotification $notification, array $channels, AnonymousNotifiable $notifiable) use (&$url): bool {
        $url = $notification->data->url;

        return $notifiable->routes['mail'] === 'new@example.com';
    });

    expect(Authentication::email()->confirmChange(tokenFromUrl($url), sessionContext())->accountEmail())->toBe('new@example.com');
    Event::assertDispatched(EmailChanged::class);
});

it('applies the guard switches', function (): void {
    $this->configureGuard('users', ['verification.mode' => 'off', 'email_change.enabled' => false]);
    $user = User::factory()->unverified()->create();

    expect(fn () => Authentication::email()->sendVerification($user))->toThrow(LoginMethodDisabled::class)
        ->and(fn () => Authentication::email()->requestChange($user, new EmailChangeData('new@example.com', sessionContext())))->toThrow(LoginMethodDisabled::class);
});
