<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Jobs\DeliverAuthenticationNotification;
use RoundlyConsulting\Auth\Notifications\AccountExistsNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Notifications\NewDeviceLoginNotification;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('delivers after the response by default', function (): void {
    Bus::fake();
    $this->configureGuard('users', ['notifications.delivery' => 'after_response']);
    $user = User::factory()->create();

    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());

    Bus::assertDispatchedAfterResponse(DeliverAuthenticationNotification::class, fn (DeliverAuthenticationNotification $job): bool => $job->notification instanceof MagicLinkNotification);
});

it('queues on the configured connection and queue', function (): void {
    Bus::fake();
    $this->configureGuard('users', ['notifications.delivery' => 'queue', 'notifications.connection' => 'redis', 'notifications.queue' => 'mail']);
    $user = User::factory()->create();

    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());

    Bus::assertDispatched(DeliverAuthenticationNotification::class, fn (DeliverAuthenticationNotification $job): bool => $job->connection === 'redis' && $job->queue === 'mail');
});

it('sends the notification when the delivery job runs', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $notification = new MagicLinkNotification(new NotificationData('users', url: 'https://x.test#token=abc'));

    (new DeliverAuthenticationNotification($user, $notification))->handle();

    Notification::assertSentTo($user, MagicLinkNotification::class);
});

it('keeps plaintext secrets out of the queue store', function (): void {
    Schema::create('jobs', function (Blueprint $table): void {
        $table->id();
        $table->string('queue')->index();
        $table->longText('payload');
        $table->unsignedTinyInteger('attempts');
        $table->unsignedInteger('reserved_at')->nullable();
        $table->unsignedInteger('available_at');
        $table->unsignedInteger('created_at');
    });
    config()->set('queue.default', 'database');
    config()->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    $this->configureGuard('users', ['notifications.delivery' => 'queue']);
    $user = User::factory()->create();

    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext());

    $payload = (string) DB::table('jobs')->value('payload');

    expect($payload)->not->toBe('')
        ->and($payload)->not->toContain('EmailOtpNotification')
        ->and($payload)->not->toContain($user->email)
        ->and(json_decode($payload, true)['data']['command'] ?? '')->not->toContain('code');
});

it('localizes mail through the account locale', function (): void {
    app('translator')->addLines(['notifications.magic_link.subject' => 'Váš prihlasovací odkaz'], 'sk', 'authentication');
    $user = User::factory()->create(['locale' => 'sk']);
    $notification = new MagicLinkNotification(new NotificationData('users', url: 'https://x.test#token=abc', expiresAt: CarbonImmutable::now()->addMinutes(15)));

    Notification::fake();
    Notification::send($user, $notification);

    Notification::assertSentTo($user, MagicLinkNotification::class, function (MagicLinkNotification $sent, array $channels, object $notifiable, ?string $locale): bool {
        app()->setLocale($locale ?? 'en');

        return $locale === 'sk' && $sent->toMail($notifiable)->subject === 'Váš prihlasovací odkaz';
    });
    app()->setLocale('en');
});

it('renders the copy, the action, the code and the expiry', function (): void {
    $mail = (new NewDeviceLoginNotification(new NotificationData('users', url: 'https://x.test/sessions', code: '123456', expiresAt: CarbonImmutable::now()->addMinutes(10), replacements: ['ip' => '1.2.3.4', 'user_agent' => 'UA', 'time' => 'now'])))
        ->toMail(new AnonymousNotifiable);

    expect($mail->subject)->toContain('New sign-in')
        ->and(implode(' ', $mail->introLines))->toContain('1.2.3.4')->toContain('123456')
        ->and($mail->actionUrl)->toBe('https://x.test/sessions')
        ->and(implode(' ', $mail->outroLines))->toContain('10 minutes');
});

it('skips a notification configured as null and rejects a non-notification class', function (): void {
    Notification::fake();
    $user = User::factory()->create();

    $this->configureGuard('users', ['notifications.classes.new_device' => null]);
    app(NotificationDispatcher::class)->send(app(GuardRegistry::class)->get('users'), NotificationType::NewDevice, $user, new NotificationData('users'));
    Notification::assertNothingSent();

    $this->configureGuard('users', ['notifications.classes.new_device' => stdClass::class]);
    expect(fn () => app(NotificationDispatcher::class)->send(app(GuardRegistry::class)->get('users'), NotificationType::NewDevice, $user, new NotificationData('users')))
        ->toThrow(AuthenticationMisconfigured::class);
});

it('mails an arbitrary address with a locale', function (): void {
    Notification::fake();

    app(NotificationDispatcher::class)->sendTo(app(GuardRegistry::class)->get('users'), NotificationType::AccountExists, 'someone@example.com', new NotificationData('users'), 'sk');

    Notification::assertSentOnDemand(AccountExistsNotification::class, fn ($notification, $channels, $notifiable, $locale): bool => $locale === 'sk' && $notifiable->routes['mail'] === 'someone@example.com');
});
