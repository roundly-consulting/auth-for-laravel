<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Email;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Email\VerifyEmail;
use RoundlyConsulting\Auth\Http\Requests\VerifyEmailRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class VerifyEmailController
{
    public function __invoke(VerifyEmailRequest $request, VerifyEmail $verify): JsonResponse
    {
        $data = $request->toData();
        $verify->execute($request->guardConfig()->name(), $data->token, $data->email, $data->context);

        return LoginResponse::status('verified', 200);
    }
}
