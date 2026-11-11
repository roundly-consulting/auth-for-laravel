<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passwords;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Passwords\ResetPassword;
use RoundlyConsulting\Auth\Http\Requests\ResetPasswordRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ResetPasswordController
{
    public function __invoke(ResetPasswordRequest $request, ResetPassword $reset): TokenPairResource|ChallengeResource|JsonResponse
    {
        $result = $reset->execute($request->guardConfig()->name(), $request->toData());

        return $result === null ? new JsonResponse(['status' => 'reset']) : LoginResponse::resource($result);
    }
}
