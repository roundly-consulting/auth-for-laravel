<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passkeys;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Passkeys\RemovePasskey;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Exceptions\PasskeyNotFound;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;

final class RemovePasskeyController
{
    public function __invoke(Request $request, RemovePasskey $remove, SensitiveActionGate $gate, string $passkey): JsonResponse
    {
        if (! ctype_digit($passkey)) {
            throw new PasskeyNotFound;
        }

        $guard = RequestGuard::config($request);
        $account = RequestGuard::requireAccount($request, $guard);
        $current = CurrentToken::fromRequest($request, $guard);

        $gate->check($guard, SensitiveAction::RemovePasskey, $current, $account);

        $tokens = $remove->execute($guard->name(), $account, (int) $passkey, $current, SessionContext::fromRequest($request, $guard));

        return LoginResponse::withTokens(['status' => 'removed'], $tokens, $request);
    }
}
