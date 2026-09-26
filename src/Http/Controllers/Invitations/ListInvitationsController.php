<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use RoundlyConsulting\Auth\Actions\Invitations\ListInvitations;
use RoundlyConsulting\Auth\Enums\InvitationStatus;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\InvitationResource;

final class ListInvitationsController
{
    public function __invoke(Request $request, ListInvitations $invitations): AnonymousResourceCollection
    {
        $status = $request->query('status');
        $perPage = $request->query('per_page');

        return InvitationResource::collection($invitations->execute(
            RequestGuard::name($request),
            is_string($status) ? InvitationStatus::tryFrom($status) : null,
            is_string($perPage) && ctype_digit($perPage) ? (int) $perPage : 20,
        ));
    }
}
