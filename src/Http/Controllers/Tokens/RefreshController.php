<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Tokens;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Tokens\RefreshTokenPair;
use RoundlyConsulting\Auth\Http\Requests\RefreshTokenRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class RefreshController
{
    public function __invoke(RefreshTokenRequest $request, RefreshTokenPair $refresh): JsonResponse
    {
        $data = $request->toData();

        return LoginResponse::tokens($refresh->execute($request->guardConfig()->name(), $data->refreshToken, $data->context), $request);
    }
}
