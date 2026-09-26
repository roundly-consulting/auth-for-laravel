<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\TwoFactor;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\TwoFactor\ConfirmTwoFactorEnrolment;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\CodeRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ConfirmController
{
    public function __invoke(CodeRequest $request, ConfirmTwoFactorEnrolment $confirm): JsonResponse
    {
        $guard = $request->guardConfig();
        $data = $request->toData();

        $tokens = $confirm->execute($guard->name(), RequestGuard::requireAccount($request, $guard), $data->code, CurrentToken::fromRequest($request, $guard), $data->context);

        return LoginResponse::withTokens(['status' => 'enabled'], $tokens, $request);
    }
}
