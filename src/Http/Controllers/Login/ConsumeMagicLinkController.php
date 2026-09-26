<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\ConsumeMagicLink;
use RoundlyConsulting\Auth\Http\Requests\TokenRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ConsumeMagicLinkController
{
    public function __invoke(TokenRequest $request, ConsumeMagicLink $magicLink): JsonResponse
    {
        $data = $request->toData();

        return LoginResponse::make($magicLink->execute($request->guardConfig()->name(), $data->token, $data->context), $request);
    }
}
