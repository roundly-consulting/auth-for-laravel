<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\Events\InvitationCreated;
use RoundlyConsulting\Auth\Events\InvitationRevoked;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Rules\SupportedLocale;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Creates an invitation (and sends it unless told not to). An earlier pending
 * invitation for the same address is revoked (`replace_pending`); an address that
 * already has an account is refused unless `allow_existing_email` (admin-facing, so the
 * error is fine to show). The locale must be one of the guard's `locale.supported` — it
 * becomes the new account's locale on accept.
 */
final readonly class CreateInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private SendInvitation $send,
    ) {}

    public function execute(string $guard, InvitationData $data): Invitation
    {
        $config = $this->guards->get($guard);

        if (! $config->invitationsEnabled()) {
            throw new LoginMethodDisabled;
        }

        $accounts = new AccountRepository($config);
        $email = $accounts->normalizeEmail($data->email);
        $now = CarbonImmutable::now();

        Validator::make(
            ['email' => $email, 'locale' => $data->locale],
            ['email' => ['required', 'email', 'max:255'], 'locale' => ['nullable', new SupportedLocale($config)]],
        )->validate();

        if (! $config->invitationAllowsExistingEmail() && $accounts->emailTaken($email)) {
            throw ValidationException::withMessages(['email' => __('authentication::validation.email_taken')]);
        }

        if ($config->invitationReplacesPending()) {
            Models::invitations()->where('guard', $guard)->where('email', $email)->pending($now)->get()
                ->each(static function (Invitation $pending) use ($now, $guard): void {
                    Models::invitations()->whereKey($pending->getKey())->update(['revoked_at' => $now]);
                    event(new InvitationRevoked($guard, $pending));
                });
        }

        $invitation = Models::invitations()->create([
            'guard' => $guard,
            'email' => $email,
            'inviter_type' => $data->invitedBy?->getMorphClass(),
            'inviter_id' => $data->invitedBy?->getKey(),
            'payload' => $data->payload === [] ? null : $data->payload,
            'locale' => $data->locale,
            'send_count' => 0,
            'expires_at' => $now->addSeconds($data->ttl ?? $config->invitationTtl()),
        ]);

        event(new InvitationCreated($guard, $invitation));

        if ($data->send) {
            $this->send->execute($invitation);
        }

        return $invitation->refresh();
    }
}
