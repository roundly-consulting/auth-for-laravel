<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use RoundlyConsulting\Auth\Enums\InvitationStatus;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;

final readonly class ListInvitations
{
    public function __construct(private GuardRegistry $guards) {}

    /**
     * @return LengthAwarePaginator<int, Invitation>
     */
    public function execute(string $guard, ?InvitationStatus $status = null, int $perPage = 20): LengthAwarePaginator
    {
        $this->guards->get($guard);

        return Models::invitations()
            ->where('guard', $guard)
            ->when($status !== null, static fn ($query) => $query->withStatus($status))
            ->latest()
            ->latest('id')
            ->paginate(max(1, min(100, $perPage)));
    }
}
