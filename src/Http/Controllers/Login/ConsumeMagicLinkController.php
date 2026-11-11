<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use RoundlyConsulting\Auth\Actions\Login\ConsumeMagicLink;
use RoundlyConsulting\Auth\Http\Requests\TokenRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ConsumeMagicLinkController
{
    public function __invoke(TokenRequest $request, ConsumeMagicLink $magicLink): TokenPairResource|ChallengeResource
    {
        $data = $request->toData();

        return LoginResponse::resource($magicLink->execute($request->guardConfig()->name(), $data->token, $data->context));
    }
}
