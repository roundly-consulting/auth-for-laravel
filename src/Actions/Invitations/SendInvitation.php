<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationLink;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Events\InvitationSent;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Exceptions\InvitationSendLimitReached;
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
 * copyable link. With `$notify = false` nothing is mailed: the host delivers the link
 * itself, and no send is counted (`send_count`, `last_sent_at`, the resend cooldown and
 * {@see InvitationSent} track real mails only), and a mail past `max_sends` is refused
 * ({@see InvitationSendLimitReached}). Only a pending invitation gets a link;
 * another guard's is unknown here ({@see InvitationNotFound}). The plaintext is never
 * stored or logged.
 */
final readonly class SendInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Invitation $invitation, bool $notify = true): InvitationLink
    {
        if ($invitation->guard !== $guard) {
            throw new InvitationNotFound;
        }

        if (! $invitation->isPending()) {
            throw new InvalidInvitation;
        }

        $config = $this->guards->get($guard);
        $token = Token::urlSafe(64);
        $row = Models::invitations()->whereKey($invitation->getKey())->where('guard', $guard);
        $hash = $this->hasher->link($guard, 'invitation', $token);

        if ($notify) {
            // Counted in SQL and capped at `max_sends`: concurrent sends never mail past the
            // cap, and the count is never a value read before them.
            $sent = $row->where('send_count', '<', $config->invitationMaxSends())
                ->increment('send_count', 1, ['token_hash' => $hash, 'last_sent_at' => CarbonImmutable::now()]);

            if ($sent === 0) {
                throw $invitation->refresh()->send_count >= $config->invitationMaxSends() ? new InvitationSendLimitReached : new InvalidInvitation;
            }
        } else {
            $row->update(['token_hash' => $hash]);
        }

        $invitation->refresh();
        $url = UrlTemplate::render($config, UrlKind::Invitation, $token, $invitation->email);

        if ($notify) {
            $this->notifications->sendTo($config, NotificationType::Invitation, $invitation->email, new NotificationData(
                guard: $guard,
                url: $url,
                expiresAt: $invitation->expires_at,
            ), $invitation->locale);

            event(new InvitationSent($guard, $invitation));
        }

        return new InvitationLink($invitation, $token, $url);
    }
}
