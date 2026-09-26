<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Sessions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutEverywhere;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class LogoutEverywhereController
{
    public function __invoke(Request $request, LogoutEverywhere $logout, SensitiveActionGate $gate): JsonResponse
    {
        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);

        $gate->check($guard, SensitiveAction::LogoutEverywhere, CurrentToken::fromRequest($request, $guard), $account);

        return new JsonResponse(['revoked' => $logout->execute($guard->name(), $account)]);
    }
}
