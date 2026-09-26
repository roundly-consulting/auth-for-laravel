<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use RoundlyConsulting\Auth\Actions\Invitations\RevokeInvitation;
use RoundlyConsulting\Auth\Http\InvitationRoute;
use RoundlyConsulting\Auth\Http\RequestGuard;

final class RevokeInvitationController
{
    public function __invoke(Request $request, RevokeInvitation $revoke, string $invitation): Response
    {
        $revoke->execute(InvitationRoute::resolve(RequestGuard::name($request), $invitation));

        return new Response(status: 204);
    }
}
