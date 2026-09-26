<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Email;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Email\ResendEmailVerification;
use RoundlyConsulting\Auth\Http\Requests\EmailRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ResendVerificationController
{
    public function __invoke(EmailRequest $request, ResendEmailVerification $resend): JsonResponse
    {
        $data = $request->toData();
        $resend->execute($request->guardConfig()->name(), $data->email, $data->context);

        return LoginResponse::status('sent');
    }
}
