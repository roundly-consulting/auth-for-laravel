<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Account\SendReauthenticationCode;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class SendReauthenticationCodeController
{
    public function __invoke(Request $request, SendReauthenticationCode $send): JsonResponse
    {
        $guard = RequestGuard::config($request);

        $send->execute($guard->name(), RequestGuard::requireAccount($request, $guard), SessionContext::fromRequest($request, $guard));

        return LoginResponse::status('sent');
    }
}
