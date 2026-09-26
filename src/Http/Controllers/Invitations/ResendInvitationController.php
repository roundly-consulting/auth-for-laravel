<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Invitations\ResendInvitation;
use RoundlyConsulting\Auth\Http\InvitationRoute;
use RoundlyConsulting\Auth\Http\RequestGuard;

/**
 * Re-sends the invitation; the fresh link is returned once so an admin screen can offer
 * it for copying (the response is `no-store`).
 */
final class ResendInvitationController
{
    public function __invoke(Request $request, ResendInvitation $resend, string $invitation): JsonResponse
    {
        $link = $resend->execute(InvitationRoute::resolve(RequestGuard::name($request), $invitation));

        return new JsonResponse(['status' => 'sent', 'url' => $link->url]);
    }
}
