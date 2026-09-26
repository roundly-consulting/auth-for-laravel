<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\CompletePasskeyLogin;
use RoundlyConsulting\Auth\Http\Requests\PasskeyAssertionRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class PasskeyLoginController
{
    public function __invoke(PasskeyAssertionRequest $request, CompletePasskeyLogin $login): JsonResponse
    {
        return LoginResponse::make($login->execute($request->guardConfig()->name(), $request->toData(), $request->sessionContext()), $request);
    }
}
