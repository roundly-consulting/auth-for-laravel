<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Sessions;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutCurrentSession;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;

final class LogoutController
{
    public function __invoke(Request $request, LogoutCurrentSession $logout): Response
    {
        $guard = RequestGuard::config($request);

        $logout->execute($guard->name(), RequestGuard::requireAccount($request, $guard), CurrentToken::fromRequest($request, $guard));

        return new Response(status: 204);
    }
}
