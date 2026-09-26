<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Events\EmailChanged;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\AccountExistsNotification;
use RoundlyConsulting\Auth\Notifications\ConfirmEmailChangeNotification;
use RoundlyConsulting\Auth\Notifications\EmailChangedNotification;
use RoundlyConsulting\Auth\Notifications\EmailChangeRequestedNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

function confirmationToken(): string
{
    $url = null;

    Notification::assertSentOnDemand(ConfirmEmailChangeNotification::class, function (ConfirmEmailChangeNotification $notification, array $channels, AnonymousNotifiable $notifiable) use (&$url): bool {
        $url = $notification->data->url;

        return true;
    });

    return tokenFromUrl($url);
}

it('changes the email only once the new address confirms, telling the old one twice', function (): void {
    Event::fake([EmailChanged::class]);
    $user = User::factory()->create(['email' => 'old@example.com']);
    $pair = issuePair($user);

    $this->postJson('/users/auth/email/change', ['email' => 'New@Example.com'], bearer($pair))->assertStatus(202);

    expect($user->fresh()?->email)->toBe('old@example.com');
    Notification::assertSentOnDemand(ConfirmEmailChangeNotification::class, fn ($n, $c, $notifiable): bool => $notifiable->routes['mail'] === 'new@example.com');
    Notification::assertSentOnDemand(EmailChangeRequestedNotification::class, fn ($n, $c, $notifiable): bool => $notifiable->routes['mail'] === 'old@example.com' && $n->data->replacements['new_email'] === 'new@example.com');

    $this->postJson('/users/auth/email/change/confirm', ['token' => confirmationToken()])->assertOk()->assertExactJson(['status' => 'changed']);

    expect($user->fresh()?->email)->toBe('new@example.com')
        ->and($user->fresh()?->hasVerifiedEmail())->toBeTrue();
    Notification::assertSentOnDemand(EmailChangedNotification::class, fn ($n, $c, $notifiable): bool => $notifiable->routes['mail'] === 'old@example.com');
    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    Event::assertDispatched(EmailChanged::class, fn (EmailChanged $event): bool => $event->oldEmail === 'old@example.com' && $event->newEmail === 'new@example.com');
});

it('answers a taken address the same way and notifies its owner instead', function (): void {
    $user = User::factory()->create();
    User::factory()->create(['email' => 'taken@example.com']);

    $this->postJson('/users/auth/email/change', ['email' => 'taken@example.com'], bearer(issuePair($user)))->assertStatus(202)->assertExactJson(['status' => 'sent']);

    Notification::assertSentOnDemand(AccountExistsNotification::class);
    Notification::assertNotSentTo(new AnonymousNotifiable, ConfirmEmailChangeNotification::class);
});

it('refuses the unchanged address', function (): void {
    $user = User::factory()->create();

    $this->postJson('/users/auth/email/change', ['email' => strtoupper($user->email)], bearer(issuePair($user)))->assertStatus(422)->assertJsonValidationErrors('email');
});

it('kills links sent to the old address', function (): void {
    $user = User::factory()->create(['email' => 'old@example.com']);
    Authentication::guard('users')->requestMagicLink('old@example.com', sessionContext());
    $magic = tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url);

    $this->postJson('/users/auth/email/change', ['email' => 'new@example.com'], bearer(issuePair($user)))->assertStatus(202);
    $this->postJson('/users/auth/email/change/confirm', ['token' => confirmationToken()])->assertOk();

    $this->postJson('/users/auth/login/magic-link/consume', ['token' => $magic])->assertStatus(422);
});

it('loses the race when another account claims the address first', function (): void {
    $user = User::factory()->create();

    $this->postJson('/users/auth/email/change', ['email' => 'contested@example.com'], bearer(issuePair($user)))->assertStatus(202);
    User::factory()->create(['email' => 'contested@example.com']);

    $this->postJson('/users/auth/email/change/confirm', ['token' => confirmationToken()])->assertStatus(422)->assertJsonPath('code', 'invalid_token');
});

it('refuses a confirmation after the account already changed its email elsewhere', function (): void {
    $user = User::factory()->create(['email' => 'old@example.com']);

    $this->postJson('/users/auth/email/change', ['email' => 'new@example.com'], bearer(issuePair($user)))->assertStatus(202);
    $user->forceFill(['email' => 'elsewhere@example.com'])->save();

    $this->postJson('/users/auth/email/change/confirm', ['token' => confirmationToken()])->assertStatus(422);
});

it('requires a recent authentication', function (): void {
    $this->configureGuard('users', ['tokens.access_ttl' => 7200]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
    $pair = issuePair(User::factory()->create());
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    $this->postJson('/users/auth/email/change', ['email' => 'new@example.com'], bearer($pair))->assertForbidden()->assertJsonPath('code', 'reauthentication_required');
    CarbonImmutable::setTestNow();
});
