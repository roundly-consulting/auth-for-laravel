<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Invitations\CreateInvitation;
use RoundlyConsulting\Auth\Http\Requests\CreateInvitationRequest;
use RoundlyConsulting\Auth\Http\Resources\InvitationResource;

final class CreateInvitationController
{
    public function __invoke(CreateInvitationRequest $request, CreateInvitation $create): JsonResponse
    {
        return (new InvitationResource($create->execute($request->guardConfig()->name(), $request->toData())->invitation))
            ->toResponse($request)
            ->setStatusCode(201);
    }
}
