<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\AccountResource;

final class MeController
{
    public function __invoke(Request $request): JsonResource
    {
        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);
        $resource = $guard->accountResource();

        return $resource !== null && is_subclass_of($resource, JsonResource::class)
            ? new $resource($account)
            : new AccountResource($account);
    }
}
