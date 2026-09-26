<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use RoundlyConsulting\Auth\Actions\Challenges\StartTwoFactorEnrolmentStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengeTokenRequest;
use RoundlyConsulting\Auth\Http\Resources\TwoFactorSetupResource;

final class StartTwoFactorEnrolmentController
{
    public function __invoke(ChallengeTokenRequest $request, StartTwoFactorEnrolmentStep $step): TwoFactorSetupResource
    {
        $data = $request->toData();

        return new TwoFactorSetupResource($step->execute($request->guardConfig()->name(), $data->token, $data->context));
    }
}
