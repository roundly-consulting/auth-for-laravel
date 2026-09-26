<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passwords;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Passwords\ChangePassword;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\ChangePasswordRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class ChangePasswordController
{
    public function __invoke(ChangePasswordRequest $request, ChangePassword $change): JsonResponse
    {
        $guard = $request->guardConfig();
        $tokens = $change->execute($guard->name(), RequestGuard::requireAccount($request, $guard), $request->toData());

        return LoginResponse::withTokens(['status' => 'changed'], $tokens, $request);
    }
}
