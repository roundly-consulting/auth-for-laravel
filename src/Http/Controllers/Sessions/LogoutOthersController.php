<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Sessions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutOtherSessions;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;

final class LogoutOthersController
{
    public function __invoke(Request $request, LogoutOtherSessions $logout): JsonResponse
    {
        $guard = RequestGuard::config($request);

        $revoked = $logout->execute($guard->name(), RequestGuard::requireAccount($request, $guard), CurrentToken::fromRequest($request, $guard));

        return new JsonResponse(['revoked' => $revoked]);
    }
}
