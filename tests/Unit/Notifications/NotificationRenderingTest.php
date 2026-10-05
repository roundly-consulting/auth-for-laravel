<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Notifications\AnonymousNotifiable;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Notifications\SignInBlockedNotification;
use RoundlyConsulting\Auth\Notifications\SuspiciousSessionNotification;
use RoundlyConsulting\Auth\Notifications\UnusualSignInNotification;

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

it('renders a zero-minute expiry without stray whitespace', function (string $locale, string $line): void {
    app()->setLocale($locale);

    expect(trans_choice('authentication::notifications.expiry', 0, ['minutes' => 0]))->toBe($line);
})->with([
    'en' => ['en', 'This expires in 0 minutes.'],
    'sk' => ['sk', 'Platnosť vyprší o 0 minút.'],
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
    'sk, refresh token reuse' => ['sk', 'refresh_token_reuse', 'Vo vašom účte sme zaznamenali podozrivú aktivitu (opätovne použitý token relácie) a dotknutú reláciu sme odhlásili.'],
]);

it('says a blocked sign-in signed nobody in, an unusual one is live, and neither signed a session out', function (string $class, string $locale, string $intro): void {
    app()->setLocale($locale);

    $mail = (new $class(new NotificationData('users')))->toMail(new AnonymousNotifiable);
    $text = implode(' ', [$mail->subject, ...$mail->introLines, ...$mail->outroLines]);

    expect($mail->introLines[0])->toBe($intro)
        ->and($text)->not->toContain('signed the affected session out')
        ->and($text)->not->toContain('reláciu sme odhlásili')
        ->and($text)->not->toContain(':');
})->with([
    'en, blocked' => [SignInBlockedNotification::class, 'en', 'We blocked an attempt to sign in to your account because it looked suspicious. Nobody was signed in.'],
    'en, unusual' => [UnusualSignInNotification::class, 'en', 'Someone just signed in to your account in a way that looked unusual.'],
    'sk, blocked' => [SignInBlockedNotification::class, 'sk', 'Zablokovali sme pokus o prihlásenie do vášho účtu, pretože vyzeral podozrivo. Nikto sa neprihlásil.'],
    'sk, unusual' => [UnusualSignInNotification::class, 'sk', 'Do vášho účtu sa práve niekto prihlásil spôsobom, ktorý vyzeral nezvyčajne.'],
]);

it('passes a reason it does not know through unchanged', function (): void {
    $mail = (new SuspiciousSessionNotification(new NotificationData('users', replacements: ['reason' => 'a host-supplied reason'])))
        ->toMail(new AnonymousNotifiable);

    expect($mail->introLines[0])->toContain('(a host-supplied reason)');
});
