<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Notifications\AnonymousNotifiable;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;

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
