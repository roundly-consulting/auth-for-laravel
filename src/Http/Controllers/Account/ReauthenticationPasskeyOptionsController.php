<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Account\BeginPasskeyReauthentication;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\PasskeyOptionsResource;

final class ReauthenticationPasskeyOptionsController
{
    public function __invoke(Request $request, BeginPasskeyReauthentication $begin): PasskeyOptionsResource
    {
        $guard = RequestGuard::config($request);

        return new PasskeyOptionsResource($begin->execute($guard->name(), RequestGuard::requireAccount($request, $guard), CurrentToken::fromRequest($request, $guard)));
    }
}
