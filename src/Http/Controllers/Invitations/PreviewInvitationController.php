<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Invitations;

use RoundlyConsulting\Auth\Actions\Invitations\PreviewInvitation;
use RoundlyConsulting\Auth\Http\Requests\TokenRequest;
use RoundlyConsulting\Auth\Http\Resources\InvitationPreviewResource;

final class PreviewInvitationController
{
    public function __invoke(TokenRequest $request, PreviewInvitation $preview): InvitationPreviewResource
    {
        return new InvitationPreviewResource($preview->execute($request->guardConfig()->name(), $request->toData()->token));
    }
}
