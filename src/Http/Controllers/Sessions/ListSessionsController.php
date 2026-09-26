<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Sessions;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use RoundlyConsulting\Auth\Actions\Sessions\ListSessions;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\SessionResource;

final class ListSessionsController
{
    public function __invoke(Request $request, ListSessions $sessions): AnonymousResourceCollection
    {
        $guard = RequestGuard::config($request);
        $current = CurrentToken::fromRequest($request, $guard);

        return SessionResource::collection($sessions->execute($guard->name(), RequestGuard::requireAccount($request, $guard), $current->sessionId));
    }
}
