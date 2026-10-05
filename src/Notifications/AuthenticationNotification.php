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
    /**
     * The machine-readable `:reason` values the package sends, and the
     * `notifications.refresh_token_reuse.reasons.*` line each renders as. Any other
     * value is shown as given.
     */
    private const array REASONS = [
        'refresh_token_reuse' => 'token_reuse',
    ];

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
            $mail->line(trans_choice('authentication::notifications.expiry', (int) ($replacements['minutes'] ?? $this->minutesLeft()), $replacements));
        }

        return $mail->line($this->translate("{$key}.outro", $replacements));
    }

    /**
     * @return array<string, string|int>
     */
    protected function replacements(): array
    {
        $appName = config('app.name');
        $replacements = [
            ...$this->data->replacements,
            'app' => is_string($appName) ? $appName : 'Laravel',
            'guard' => $this->data->guard,
            'code' => $this->data->code ?? '',
            'minutes' => $this->minutesLeft(),
        ];

        if (isset($replacements['reason'])) {
            $replacements['reason'] = $this->reason($replacements['reason']);
        }

        return $replacements;
    }

    /**
     * A reason the package sent, in the notification's locale (rendering runs inside it);
     * anything else unchanged. `data->replacements` keeps the machine-readable value.
     */
    private function reason(string|int $reason): string|int
    {
        if (! is_string($reason) || ! isset(self::REASONS[$reason])) {
            return $reason;
        }

        return $this->translate('authentication::notifications.refresh_token_reuse.reasons.'.self::REASONS[$reason], []);
    }

    /**
     * Whole minutes until the link or code expires, rounded up and never below one (0
     * without an expiry). The `expiry` line picks its plural form from the same value.
     */
    protected function minutesLeft(): int
    {
        return $this->data->expiresAt === null ? 0 : max(1, (int) ceil(now()->diffInSeconds($this->data->expiresAt, false) / 60));
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
