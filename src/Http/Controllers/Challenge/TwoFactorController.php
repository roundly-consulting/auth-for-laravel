<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use RoundlyConsulting\Auth\Actions\Challenges\CompleteTwoFactorStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengeCodeRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class TwoFactorController
{
    public function __invoke(ChallengeCodeRequest $request, CompleteTwoFactorStep $step): TokenPairResource|ChallengeResource
    {
        return LoginResponse::resource($step->execute($request->guardConfig()->name(), $request->toData()));
    }
}
