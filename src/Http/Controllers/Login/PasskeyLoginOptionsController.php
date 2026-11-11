<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Login\BeginPasskeyLogin;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\PasskeyRequestOptionsResource;

final class PasskeyLoginOptionsController
{
    public function __invoke(Request $request, BeginPasskeyLogin $begin): PasskeyRequestOptionsResource
    {
        $guard = RequestGuard::config($request);

        return new PasskeyRequestOptionsResource($begin->execute($guard->name(), SessionContext::fromRequest($request, $guard)));
    }
}
