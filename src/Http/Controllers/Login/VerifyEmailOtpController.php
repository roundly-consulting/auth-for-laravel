<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\VerifyEmailOtp;
use RoundlyConsulting\Auth\Http\Requests\EmailCodeRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class VerifyEmailOtpController
{
    public function __invoke(EmailCodeRequest $request, VerifyEmailOtp $otp): JsonResponse
    {
        $data = $request->toData();

        return LoginResponse::make($otp->execute($request->guardConfig()->name(), $data->email, $data->code, $data->context), $request);
    }
}
