<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Challenge;

use RoundlyConsulting\Auth\Actions\Challenges\BeginPasskeyStep;
use RoundlyConsulting\Auth\Http\Requests\ChallengeTokenRequest;
use RoundlyConsulting\Auth\Http\Resources\PasskeyOptionsResource;

final class PasskeyOptionsController
{
    public function __invoke(ChallengeTokenRequest $request, BeginPasskeyStep $step): PasskeyOptionsResource
    {
        $data = $request->toData();

        return new PasskeyOptionsResource($step->execute($request->guardConfig()->name(), $data->token, $data->context));
    }
}
