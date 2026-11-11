<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Account\BeginPasskeyReauthentication;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\PasskeyRequestOptionsResource;

final class ReauthenticationPasskeyOptionsController
{
    public function __invoke(Request $request, BeginPasskeyReauthentication $begin): PasskeyRequestOptionsResource
    {
        $guard = RequestGuard::config($request);

        return new PasskeyRequestOptionsResource($begin->execute($guard->name(), RequestGuard::requireAccount($request, $guard), CurrentToken::fromRequest($request, $guard)));
    }
}
