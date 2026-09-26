<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passkeys;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use RoundlyConsulting\Auth\Actions\Passkeys\ListPasskeys;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Passkeys\Http\Resources\PasskeyResource;

final class ListPasskeysController
{
    public function __invoke(Request $request, ListPasskeys $passkeys): AnonymousResourceCollection
    {
        $guard = RequestGuard::config($request);

        return PasskeyResource::collection($passkeys->execute($guard->name(), RequestGuard::requireAccount($request, $guard)));
    }
}
