<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Invitations\AcceptInvitation;
use RoundlyConsulting\Auth\Http\Requests\AcceptInvitationRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class AcceptInvitationController
{
    public function __invoke(AcceptInvitationRequest $request, AcceptInvitation $accept): JsonResponse
    {
        return LoginResponse::make($accept->execute($request->guardConfig()->name(), $request->toData()), $request);
    }
}
