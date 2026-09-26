<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\TwoFactor;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\TwoFactor\GetTwoFactorStatus;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\TwoFactorStatusResource;

final class StatusController
{
    public function __invoke(Request $request, GetTwoFactorStatus $status): TwoFactorStatusResource
    {
        $guard = RequestGuard::config($request);

        return new TwoFactorStatusResource($status->execute($guard->name(), RequestGuard::requireAccount($request, $guard)));
    }
}
