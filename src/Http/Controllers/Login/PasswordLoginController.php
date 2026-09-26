<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\AttemptPasswordLogin;
use RoundlyConsulting\Auth\Http\Requests\PasswordLoginRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class PasswordLoginController
{
    public function __invoke(PasswordLoginRequest $request, AttemptPasswordLogin $login): JsonResponse
    {
        return LoginResponse::make($login->execute($request->guardConfig()->name(), $request->toData(), $request->sessionContext()), $request);
    }
}
