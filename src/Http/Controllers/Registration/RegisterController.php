<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Registration;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Registration\RegisterAccount;
use RoundlyConsulting\Auth\Http\Requests\RegisterRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class RegisterController
{
    public function __invoke(RegisterRequest $request, RegisterAccount $register): TokenPairResource|ChallengeResource|JsonResponse
    {
        $result = $register->execute($request->guardConfig()->name(), $request->toData());

        return $result->login !== null
            ? LoginResponse::resource($result->login)
            : new JsonResponse(['status' => $result->status->value], 202);
    }
}
