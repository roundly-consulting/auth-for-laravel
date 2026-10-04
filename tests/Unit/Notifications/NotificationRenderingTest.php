<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Notifications\AnonymousNotifiable;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;

it('renders every notification from its own copy', function (NotificationType $type): void {
    $class = app(GuardRegistry::class)->get('users')->notificationClass($type);
    $notification = new $class(new NotificationData('users', url: 'https://x.test#token=t', code: '123456', expiresAt: CarbonImmutable::now()->addMinutes(5), replacements: ['remaining' => 2, 'new_email' => 'n@x.test', 'ip' => '1.1.1.1', 'user_agent' => 'UA', 'time' => 'now', 'reason' => 'test']));

    expect($notification)->toBeInstanceOf(AuthenticationNotification::class)
        ->and($notification->type())->toBe($type)
        ->and($notification->via(new AnonymousNotifiable))->toBe(['mail']);

    $mail = $notification->toMail(new AnonymousNotifiable);

    expect($mail->subject)->not->toContain('authentication::')
        ->and(implode(' ', [...$mail->introLines, ...$mail->outroLines]))->not->toContain('authentication::')
        ->and($mail->actionText)->not->toContain('authentication::');
})->with(NotificationType::cases());

it('pluralises the expiry line in english and slovak', function (string $locale, int $minutes, string $line): void {
    $this->freezeTime();
    app()->setLocale($locale);

    $mail = (new MagicLinkNotification(new NotificationData('users', url: 'https://x.test#token=t', expiresAt: CarbonImmutable::now()->addMinutes($minutes))))
        ->toMail(new AnonymousNotifiable);

    expect($mail->outroLines)->toContain($line);
})->with([
    'en, 1 minute' => ['en', 1, 'This expires in 1 minute.'],
    'en, 15 minutes' => ['en', 15, 'This expires in 15 minutes.'],
    'sk, 1 minute' => ['sk', 1, 'Platnosť vyprší o 1 minútu.'],
    'sk, 3 minutes' => ['sk', 3, 'Platnosť vyprší o 3 minúty.'],
    'sk, 15 minutes' => ['sk', 15, 'Platnosť vyprší o 15 minút.'],
]);

it('keeps a published single-form expiry override working', function (): void {
    $this->freezeTime();
    trans('authentication::notifications.expiry');
    app('translator')->addLines(['notifications.expiry' => 'Valid for :minutes min.'], 'en', 'authentication');

    $mail = (new MagicLinkNotification(new NotificationData('users', url: 'https://x.test#token=t', expiresAt: CarbonImmutable::now()->addMinutes(1))))
        ->toMail(new AnonymousNotifiable);

    expect($mail->outroLines)->toContain('Valid for 1 min.');
});
