<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyEnrolmentStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Http\Requests\ChallengePasskeyRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class PasskeyEnrolmentController
{
    public function __invoke(ChallengePasskeyRequest $request, CompletePasskeyEnrolmentStep $step): JsonResponse
    {
        return LoginResponse::make($step->execute($request->guardConfig()->name(), $request->toData(FactorMethod::PasskeyEnrolment)), $request);
    }
}
