<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\TwoFactor;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\TwoFactor\DisableTwoFactor;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class DisableController
{
    public function __invoke(Request $request, DisableTwoFactor $disable, SensitiveActionGate $gate): JsonResponse
    {
        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);
        $current = CurrentToken::fromRequest($request, $guard);

        $gate->check($guard, SensitiveAction::DisableTwoFactor, $current, $account);

        $tokens = $disable->execute($guard->name(), $account, $current, SessionContext::fromRequest($request, $guard));

        return new JsonResponse(['status' => 'disabled', 'tokens' => $tokens === null ? null : new TokenPairResource($tokens)]);
    }
}
