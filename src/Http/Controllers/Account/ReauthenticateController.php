<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Account\Reauthenticate;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\ReauthenticateRequest;

final class ReauthenticateController
{
    public function __invoke(ReauthenticateRequest $request, Reauthenticate $reauthenticate): JsonResponse
    {
        $guard = $request->guardConfig();
        $until = $reauthenticate->execute($guard->name(), RequestGuard::requireAccount($request, $guard), $request->toData());

        return new JsonResponse(['status' => 'confirmed', 'confirmed_until' => $until->toIso8601ZuluString()]);
    }
}
