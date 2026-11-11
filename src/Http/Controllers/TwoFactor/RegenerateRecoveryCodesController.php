<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\TwoFactor;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\TwoFactor\RegenerateRecoveryCodes;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\RecoveryCodesResource;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class RegenerateRecoveryCodesController
{
    public function __invoke(Request $request, RegenerateRecoveryCodes $regenerate, SensitiveActionGate $gate): RecoveryCodesResource
    {
        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);
        $current = CurrentToken::fromRequest($request, $guard);

        $gate->check($guard, SensitiveAction::RegenerateRecoveryCodes, $current, $account);

        return new RecoveryCodesResource($regenerate->execute($guard->name(), $account, $current, SessionContext::fromRequest($request, $guard)));
    }
}
