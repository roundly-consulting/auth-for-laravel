<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passwords;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Passwords\RequestPasswordReset;
use RoundlyConsulting\Auth\Http\Requests\EmailRequest;

final class ForgotPasswordController
{
    public function __invoke(EmailRequest $request, RequestPasswordReset $reset): JsonResponse
    {
        $data = $request->toData();
        $reset->execute($request->guardConfig()->name(), $data->email, $data->context);

        return new JsonResponse(['status' => 'sent'], 202);
    }
}
