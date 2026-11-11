<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengePasskeyRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class PasskeyController
{
    public function __invoke(ChallengePasskeyRequest $request, CompletePasskeyStep $step): TokenPairResource|ChallengeResource
    {
        return LoginResponse::resource($step->execute($request->guardConfig()->name(), $request->toData()));
    }
}
