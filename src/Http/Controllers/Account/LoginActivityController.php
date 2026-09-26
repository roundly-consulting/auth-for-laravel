<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use RoundlyConsulting\Auth\Actions\Activity\ListLoginActivity;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\LoginActivityResource;

final class LoginActivityController
{
    public function __invoke(Request $request, ListLoginActivity $activity): AnonymousResourceCollection
    {
        $guard = RequestGuard::config($request);
        $perPage = $request->query('per_page');

        return LoginActivityResource::collection($activity->execute(
            $guard->name(),
            RequestGuard::requireAccount($request, $guard),
            is_string($perPage) && ctype_digit($perPage) ? (int) $perPage : 20,
        ));
    }
}
