<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use RoundlyConsulting\Auth\Actions\Challenges\ConfirmTwoFactorEnrolmentStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Http\Requests\ChallengeCodeRequest;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ConfirmTwoFactorEnrolmentController
{
    public function __invoke(ChallengeCodeRequest $request, ConfirmTwoFactorEnrolmentStep $step): TokenPairResource|ChallengeResource
    {
        return LoginResponse::resource($step->execute($request->guardConfig()->name(), $request->toData(FactorMethod::TotpEnrolment)));
    }
}
