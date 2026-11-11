<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Email;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Email\ConfirmEmailChange;
use RoundlyConsulting\Auth\Http\Requests\TokenRequest;

final class ConfirmEmailChangeController
{
    public function __invoke(TokenRequest $request, ConfirmEmailChange $confirm): JsonResponse
    {
        $data = $request->toData();
        $confirm->execute($request->guardConfig()->name(), $data->token, $data->context);

        return new JsonResponse(['status' => 'changed']);
    }
}
