<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;

/**
 * The base of every notification the package sends. The copy lives in
 * `authentication::notifications.<type>.*` (publish `authentication-translations` to
 * change it); swap a class per guard through `notifications.classes.<type>`.
 *
 * Never implements `ShouldQueue`: queued delivery goes through the encrypted
 * `DeliverAuthenticationNotification` job only, because an instance holds the
 * plaintext link or code.
 */
abstract class AuthenticationNotification extends Notification
{
    public function __construct(public readonly NotificationData $data) {}

    abstract public function type(): NotificationType;

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $key = 'authentication::notifications.'.$this->type()->value;
        $replacements = $this->replacements();

        $mail = (new MailMessage)
            ->subject($this->translate("{$key}.subject", $replacements))
            ->line($this->translate("{$key}.intro", $replacements));

        if ($this->data->code !== null) {
            $mail->line($this->translate('authentication::notifications.code_line', $replacements));
        }

        if ($this->data->url !== null) {
            $mail->action($this->translate("{$key}.action", $replacements), $this->data->url);
        }

        if ($this->data->expiresAt !== null) {
            $mail->line($this->translate('authentication::notifications.expiry', $replacements));
        }

        return $mail->line($this->translate("{$key}.outro", $replacements));
    }

    /**
     * @return array<string, string|int>
     */
    protected function replacements(): array
    {
        $appName = config('app.name');

        return [
            ...$this->data->replacements,
            'app' => is_string($appName) ? $appName : 'Laravel',
            'guard' => $this->data->guard,
            'code' => $this->data->code ?? '',
            'minutes' => $this->data->expiresAt === null ? 0 : max(1, (int) ceil(now()->diffInSeconds($this->data->expiresAt, false) / 60)),
        ];
    }

    /**
     * @param  array<string, string|int>  $replacements
     */
    protected function translate(string $key, array $replacements): string
    {
        $line = __($key, $replacements);

        return is_string($line) ? $line : $key;
    }
}
