<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengePasskeyRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class PasskeyController
{
    public function __invoke(ChallengePasskeyRequest $request, CompletePasskeyStep $step): JsonResponse
    {
        return LoginResponse::make($step->execute($request->guardConfig()->name(), $request->toData()), $request);
    }
}
