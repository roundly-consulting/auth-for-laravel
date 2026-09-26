<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Registration;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Registration\RegisterAccount;
use RoundlyConsulting\Auth\Http\Requests\RegisterRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class RegisterController
{
    public function __invoke(RegisterRequest $request, RegisterAccount $register): JsonResponse
    {
        $result = $register->execute($request->guardConfig()->name(), $request->toData());

        return $result->login !== null
            ? LoginResponse::make($result->login, $request)
            : LoginResponse::status($result->status->value);
    }
}
