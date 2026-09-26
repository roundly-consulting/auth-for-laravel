<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Account\UpdateLocale;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\UpdateLocaleRequest;

final class UpdateLocaleController
{
    public function __invoke(UpdateLocaleRequest $request, UpdateLocale $update): JsonResponse
    {
        $guard = $request->guardConfig();
        $account = $update->execute($guard->name(), RequestGuard::requireAccount($request, $guard), $request->toData());

        return new JsonResponse(['locale' => $account->accountLocale(), 'timezone' => $account->accountTimezone()]);
    }
}
