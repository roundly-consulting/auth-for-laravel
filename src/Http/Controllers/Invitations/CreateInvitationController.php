<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Invitations\CreateInvitation;
use RoundlyConsulting\Auth\Http\Requests\CreateInvitationRequest;
use RoundlyConsulting\Auth\Http\Resources\InvitationResource;

/**
 * 201 with the invitation (`data`) and its link (`url`) — shown once, mailed or not, so
 * an admin can deliver a `send: false` invitation through another channel (as resend
 * does).
 */
final class CreateInvitationController
{
    public function __invoke(CreateInvitationRequest $request, CreateInvitation $create): JsonResponse
    {
        $link = $create->execute($request->guardConfig()->name(), $request->toData());

        return (new InvitationResource($link->invitation))
            ->additional(['url' => $link->url])
            ->toResponse($request)
            ->setStatusCode(201);
    }
}
