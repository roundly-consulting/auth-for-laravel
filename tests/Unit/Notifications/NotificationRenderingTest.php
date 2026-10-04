<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Notifications\AnonymousNotifiable;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Notifications\SuspiciousSessionNotification;

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

it('renders the suspicious-activity reason in the mail locale', function (string $locale, string $reason, string $intro): void {
    app()->setLocale($locale);

    $mail = (new SuspiciousSessionNotification(new NotificationData('users', replacements: ['reason' => $reason])))
        ->toMail(new AnonymousNotifiable);

    expect($mail->introLines[0])->toBe($intro);
})->with([
    'en, refresh token reuse' => ['en', 'refresh_token_reuse', 'We noticed suspicious activity on your account (a reused session token) and signed the affected session out.'],
    'en, blocked sign-in' => ['en', 'blocked sign-in', 'We noticed suspicious activity on your account (a blocked sign-in attempt) and signed the affected session out.'],
    'en, unusual sign-in' => ['en', 'unusual sign-in', 'We noticed suspicious activity on your account (an unusual sign-in) and signed the affected session out.'],
    'sk, refresh token reuse' => ['sk', 'refresh_token_reuse', 'Vo vašom účte sme zaznamenali podozrivú aktivitu (opätovne použitý token relácie) a dotknutú reláciu sme odhlásili.'],
    'sk, blocked sign-in' => ['sk', 'blocked sign-in', 'Vo vašom účte sme zaznamenali podozrivú aktivitu (zablokovaný pokus o prihlásenie) a dotknutú reláciu sme odhlásili.'],
    'sk, unusual sign-in' => ['sk', 'unusual sign-in', 'Vo vašom účte sme zaznamenali podozrivú aktivitu (nezvyčajné prihlásenie) a dotknutú reláciu sme odhlásili.'],
]);

it('passes a reason it does not know through unchanged', function (): void {
    $mail = (new SuspiciousSessionNotification(new NotificationData('users', replacements: ['reason' => 'a host-supplied reason'])))
        ->toMail(new AnonymousNotifiable);

    expect($mail->introLines[0])->toContain('(a host-supplied reason)');
});
