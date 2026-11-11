<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passkeys;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Passkeys\RegisterPasskey;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\RegisterPasskeyRequest;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;
use RoundlyConsulting\Passkeys\Http\Resources\PasskeyResource;

final class RegisterPasskeyController
{
    public function __invoke(RegisterPasskeyRequest $request, RegisterPasskey $register, SensitiveActionGate $gate): JsonResponse
    {
        $guard = $request->guardConfig();
        $account = RequestGuard::requireAccount($request, $guard);
        $current = CurrentToken::fromRequest($request, $guard);

        $gate->check($guard, SensitiveAction::RegisterPasskey, $current, $account);

        $data = $request->toData();
        $result = $register->execute($guard->name(), $account, $data->response, $data->name, $current, $data->context);

        return new JsonResponse([
            'passkey' => new PasskeyResource($result->passkey),
            'tokens' => $result->tokens === null ? null : new TokenPairResource($result->tokens),
        ], 201);
    }
}
