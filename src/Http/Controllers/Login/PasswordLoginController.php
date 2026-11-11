<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use RoundlyConsulting\Auth\Actions\Login\AttemptPasswordLogin;
use RoundlyConsulting\Auth\Http\Requests\PasswordLoginRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class PasswordLoginController
{
    public function __invoke(PasswordLoginRequest $request, AttemptPasswordLogin $login): TokenPairResource|ChallengeResource
    {
        return LoginResponse::resource($login->execute($request->guardConfig()->name(), $request->toData(), $request->sessionContext()));
    }
}
