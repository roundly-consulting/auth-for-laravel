<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Sessions;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutSession;
use RoundlyConsulting\Auth\Http\RequestGuard;

final class RevokeSessionController
{
    public function __invoke(Request $request, LogoutSession $logout, string $session): Response
    {
        $guard = RequestGuard::config($request);

        $logout->execute($guard->name(), RequestGuard::requireAccount($request, $guard), $session);

        return new Response(status: 204);
    }
}
