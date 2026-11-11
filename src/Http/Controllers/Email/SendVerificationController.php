<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Email;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailVerification;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Http\RequestGuard;

final class SendVerificationController
{
    public function __invoke(Request $request, RequestEmailVerification $send): JsonResponse
    {
        $guard = RequestGuard::config($request);

        $send->execute($guard->name(), RequestGuard::requireAccount($request, $guard), SessionContext::fromRequest($request, $guard));

        return new JsonResponse(['status' => 'sent'], 202);
    }
}
