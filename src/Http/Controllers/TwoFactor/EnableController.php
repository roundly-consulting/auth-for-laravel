<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\TwoFactor;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\TwoFactor\StartTwoFactorEnrolment;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\TwoFactorSetupResource;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class EnableController
{
    public function __invoke(Request $request, StartTwoFactorEnrolment $start, SensitiveActionGate $gate): TwoFactorSetupResource
    {
        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);

        $gate->check($guard, SensitiveAction::EnableTwoFactor, CurrentToken::fromRequest($request, $guard), $account);

        return new TwoFactorSetupResource($start->execute($guard->name(), $account));
    }
}
