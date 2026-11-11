<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use RoundlyConsulting\Auth\Actions\Login\VerifyEmailOtp;
use RoundlyConsulting\Auth\Http\Requests\EmailCodeRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class VerifyEmailOtpController
{
    public function __invoke(EmailCodeRequest $request, VerifyEmailOtp $otp): TokenPairResource|ChallengeResource
    {
        $data = $request->toData();

        return LoginResponse::resource($otp->execute($request->guardConfig()->name(), $data->email, $data->code, $data->context));
    }
}
