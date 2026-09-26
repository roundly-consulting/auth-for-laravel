<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationDelivery;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Jobs\DeliverAuthenticationNotification;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;

/**
 * Sends a notification the way the guard is configured to:
 *
 *  - `after_response` (default) — behind the response, so a known account's response
 *    is not measurably slower than an unknown one's (timing enumeration). Inside a
 *    queue worker there is no response to wait for — and the worker's "after" is its
 *    exit — so it is sent inline there;
 *  - `queue` — through the encrypted job on `notifications.connection/queue`;
 *  - `sync` — inline (development only).
 *
 * A notification class configured as null is simply not sent.
 */
final class NotificationDispatcher
{
    /**
     * Notify an account. Models with Laravel's `Notifiable` are notified directly (their
     * own routing and `preferredLocale()` apply); others are mailed at their address.
     */
    public function send(GuardConfig $guard, NotificationType $type, Account $account, NotificationData $data): void
    {
        if (method_exists($account, 'routeNotificationFor')) {
            $this->dispatch($guard, $type, $account, $data, null);

            return;
        }

        $email = $account->accountEmail();

        if ($email !== null) {
            $this->dispatch($guard, $type, (new AnonymousNotifiable)->route('mail', $email), $data, $account->preferredLocale());
        }
    }

    /**
     * Mail an address that is not (or not yet) an account's current one: the new address
     * of an email change, the old one, an invitee.
     */
    public function sendTo(GuardConfig $guard, NotificationType $type, string $email, NotificationData $data, ?string $locale): void
    {
        $this->dispatch($guard, $type, (new AnonymousNotifiable)->route('mail', $email), $data, $locale);
    }

    private function dispatch(GuardConfig $guard, NotificationType $type, object $notifiable, NotificationData $data, ?string $locale): void
    {
        $class = $guard->notificationClass($type);

        if ($class === null) {
            return;
        }

        if (! is_subclass_of($class, AuthenticationNotification::class)) {
            throw AuthenticationMisconfigured::because("authentication.guards.{$guard->name()}.notifications.classes.{$type->value} must extend ".AuthenticationNotification::class.'.');
        }

        $notification = new $class($data);

        if ($locale !== null) {
            $notification->locale($locale);
        }

        $delivery = $guard->notificationDelivery();

        if ($delivery === NotificationDelivery::AfterResponse && $this->insideQueueWorker()) {
            $delivery = NotificationDelivery::Sync;
        }

        match ($delivery) {
            NotificationDelivery::Sync => Notification::sendNow($notifiable, $notification),
            NotificationDelivery::AfterResponse => Bus::dispatchAfterResponse(new DeliverAuthenticationNotification($notifiable, $notification)),
            NotificationDelivery::Queue => Bus::dispatch(
                (new DeliverAuthenticationNotification($notifiable, $notification))
                    ->onConnection($guard->notificationConnection())
                    ->onQueue($guard->notificationQueue()),
            ),
        };
    }

    /**
     * A long-running worker process (`queue:listen` runs its jobs through `queue:work`):
     * callbacks deferred "after the response" would only run when it exits.
     */
    private function insideQueueWorker(): bool
    {
        return app()->runningConsoleCommand('queue:work', 'horizon:work');
    }
}
