<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use RoundlyConsulting\Auth\Actions\Challenges\BeginPasskeyEnrolmentStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengeTokenRequest;
use RoundlyConsulting\Auth\Http\Resources\PasskeyCreationOptionsResource;

final class PasskeyEnrolmentOptionsController
{
    public function __invoke(ChallengeTokenRequest $request, BeginPasskeyEnrolmentStep $step): PasskeyCreationOptionsResource
    {
        $data = $request->toData();

        return new PasskeyCreationOptionsResource($step->execute($request->guardConfig()->name(), $data->token, $data->context));
    }
}
