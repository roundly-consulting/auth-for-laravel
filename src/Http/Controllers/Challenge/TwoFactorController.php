<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Challenges\CompleteTwoFactorStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengeCodeRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class TwoFactorController
{
    public function __invoke(ChallengeCodeRequest $request, CompleteTwoFactorStep $step): JsonResponse
    {
        return LoginResponse::make($step->execute($request->guardConfig()->name(), $request->toData()), $request);
    }
}
