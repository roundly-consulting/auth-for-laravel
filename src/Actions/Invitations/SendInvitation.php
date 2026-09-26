<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationLink;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Events\InvitationSent;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Auth\Support\UrlTemplate;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * Mints a FRESH token for every send (the previous link dies), mails it in the
 * invitation's locale, and returns the link once — an admin UI may also show it as a
 * copyable link. The plaintext is never stored or logged.
 */
final readonly class SendInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(Invitation $invitation, bool $notify = true): InvitationLink
    {
        $guard = $this->guards->get($invitation->guard);
        $token = Token::urlSafe(64);

        Models::invitations()->whereKey($invitation->getKey())->update([
            'token_hash' => $this->hasher->link($guard->name(), 'invitation', $token),
            'send_count' => $invitation->send_count + 1,
            'last_sent_at' => CarbonImmutable::now(),
        ]);

        $invitation->refresh();
        $url = UrlTemplate::render($guard, UrlKind::Invitation, $token, $invitation->email);

        if ($notify) {
            $this->notifications->sendTo($guard, NotificationType::Invitation, $invitation->email, new NotificationData(
                guard: $guard->name(),
                url: $url,
                expiresAt: $invitation->expires_at,
            ), $invitation->locale);
        }

        event(new InvitationSent($guard->name(), $invitation));

        return new InvitationLink($invitation, $token, $url);
    }
}
