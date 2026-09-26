<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\RequestEmailOtp;
use RoundlyConsulting\Auth\Http\Requests\EmailRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class RequestEmailOtpController
{
    public function __invoke(EmailRequest $request, RequestEmailOtp $otp): JsonResponse
    {
        $data = $request->toData();
        $otp->execute($request->guardConfig()->name(), $data->email, $data->context);

        return LoginResponse::status('sent');
    }
}
