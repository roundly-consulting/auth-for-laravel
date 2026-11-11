<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Tokens;

use RoundlyConsulting\Auth\Actions\Tokens\RefreshTokenPair;
use RoundlyConsulting\Auth\Http\Requests\RefreshTokenRequest;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;

final class RefreshController
{
    public function __invoke(RefreshTokenRequest $request, RefreshTokenPair $refresh): TokenPairResource
    {
        $data = $request->toData();

        return new TokenPairResource($refresh->execute($request->guardConfig()->name(), $data->refreshToken, $data->context));
    }
}
