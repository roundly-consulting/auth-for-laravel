<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\RequestEmailOtp;
use RoundlyConsulting\Auth\Http\Requests\EmailRequest;

final class RequestEmailOtpController
{
    public function __invoke(EmailRequest $request, RequestEmailOtp $otp): JsonResponse
    {
        $data = $request->toData();
        $otp->execute($request->guardConfig()->name(), $data->email, $data->context);

        return new JsonResponse(['status' => 'sent'], 202);
    }
}
