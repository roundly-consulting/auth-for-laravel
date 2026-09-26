<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Email;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Account\EnsureRecentlyAuthenticated;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailChange;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\RequestEmailChangeRequest;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;

final class RequestEmailChangeController
{
    public function __invoke(RequestEmailChangeRequest $request, RequestEmailChange $change, EnsureRecentlyAuthenticated $recent): JsonResponse
    {
        $guard = $request->guardConfig();
        $account = RequestGuard::requireAccount($request, $guard);

        if ($guard->emailChangeRequiresReauthentication() || $guard->requiresReauthentication(SensitiveAction::ChangeEmail)) {
            $recent->execute($guard->name(), CurrentToken::fromRequest($request, $guard), null, $account);
        }

        $change->execute($guard->name(), $account, $request->toData());

        return LoginResponse::status('sent');
    }
}
