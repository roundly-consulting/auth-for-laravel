<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use RoundlyConsulting\Auth\Actions\Invitations\AcceptInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\CreateInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\ListInvitations;
use RoundlyConsulting\Auth\Actions\Invitations\PreviewInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\ResendInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\RevokeInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\SendInvitation;
use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationLink;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationResult;
use RoundlyConsulting\Auth\Enums\InvitationStatus;
use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;
use SensitiveParameter;

/**
 * Invitations of one guard — `Authentication::invitations()` /
 * `Authentication::guard('clients')->invitations()`. Scoped: another guard's invitation
 * is unknown here ({@see InvitationNotFound}), whether passed as a model or an id.
 */
final readonly class InvitationsContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * Create an invitation and return its link once. Mailed to the invitee unless
     * `send: false` — then deliver `$link->url` yourself.
     */
    public function create(InvitationData $data): InvitationLink
    {
        return $this->make(CreateInvitation::class)->execute($this->guardName(), $data);
    }

    /**
     * Accept with the invitation's token — creates the account; like `register()`.
     */
    public function accept(AcceptInvitationData $data): RegistrationResult
    {
        return $this->make(AcceptInvitation::class)->execute($this->guardName(), $data);
    }

    /**
     * The guard's invitations, newest first, optionally by status.
     *
     * @return LengthAwarePaginator<int, Invitation>
     */
    public function paginate(?InvitationStatus $status = null, int $perPage = 20): LengthAwarePaginator
    {
        return $this->make(ListInvitations::class)->execute($this->guardName(), $status, $perPage);
    }

    /**
     * The pending invitation behind a token (an "accept your invitation" screen).
     */
    public function preview(#[SensitiveParameter] string $token): Invitation
    {
        return $this->make(PreviewInvitation::class)->execute($this->guardName(), $token);
    }

    /**
     * One of this guard's invitations by id, or null.
     */
    public function find(int $id): ?Invitation
    {
        return Models::invitations()->where('guard', $this->guardName())->whereKey($id)->first();
    }

    /**
     * Mail a fresh link (the old one dies), within `resend_cooldown` and `max_sends`.
     */
    public function resend(Invitation|int $invitation): InvitationLink
    {
        return $this->make(ResendInvitation::class)->execute($this->guardName(), $this->resolve($invitation));
    }

    /**
     * Revoke a pending invitation (idempotent).
     */
    public function revoke(Invitation|int $invitation): void
    {
        $this->make(RevokeInvitation::class)->execute($this->guardName(), $this->resolve($invitation));
    }

    /**
     * Mint a fresh copyable link WITHOUT mailing it. The previous link — including a
     * mailed one — dies.
     */
    public function link(Invitation|int $invitation): InvitationLink
    {
        return $this->make(SendInvitation::class)->execute($this->guardName(), $this->resolve($invitation), notify: false);
    }

    private function resolve(Invitation|int $invitation): Invitation
    {
        return $invitation instanceof Invitation ? $invitation : ($this->find($invitation) ?? throw new InvitationNotFound);
    }
}
