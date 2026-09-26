<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Email;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailChange;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\RequestEmailChangeRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class RequestEmailChangeController
{
    public function __invoke(RequestEmailChangeRequest $request, RequestEmailChange $change, SensitiveActionGate $gate): JsonResponse
    {
        $guard = $request->guardConfig();
        $account = RequestGuard::requireAccount($request, $guard);

        // `email_change.require_reauthentication = false` switches the gate off; otherwise
        // `reauthentication.required_for` decides, like every other sensitive action.
        if ($guard->emailChangeRequiresReauthentication()) {
            $gate->check($guard, SensitiveAction::ChangeEmail, CurrentToken::fromRequest($request, $guard), $account);
        }

        $change->execute($guard->name(), $account, $request->toData());

        return LoginResponse::status('sent');
    }
}
