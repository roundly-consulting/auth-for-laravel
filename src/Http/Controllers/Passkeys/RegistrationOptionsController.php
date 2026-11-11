<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passkeys;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Passkeys\BeginPasskeyRegistration;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Resources\PasskeyCreationOptionsResource;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class RegistrationOptionsController
{
    public function __invoke(Request $request, BeginPasskeyRegistration $begin, SensitiveActionGate $gate): PasskeyCreationOptionsResource
    {
        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);

        $gate->check($guard, SensitiveAction::RegisterPasskey, CurrentToken::fromRequest($request, $guard), $account);

        return new PasskeyCreationOptionsResource($begin->execute($guard->name(), $account));
    }
}
