<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Notifications\AuthenticationNotification;

/**
 * Delivers one authentication notification after the response or on a queue. Encrypted
 * (`ShouldBeEncrypted`): the serialized notification holds the plaintext link/code, and
 * must not sit readable in the queue store or `failed_jobs`.
 */
final class DeliverAuthenticationNotification implements ShouldBeEncrypted, ShouldQueue
{
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public function __construct(
        public readonly object $notifiable,
        public readonly AuthenticationNotification $notification,
    ) {}

    public function handle(): void
    {
        Notification::sendNow($this->notifiable, $this->notification);
    }
}
