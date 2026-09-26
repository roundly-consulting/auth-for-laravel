<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Passkeys;

use RoundlyConsulting\Auth\Actions\Passkeys\RenamePasskey;
use RoundlyConsulting\Auth\Exceptions\PasskeyNotFound;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\Requests\RenamePasskeyRequest;
use RoundlyConsulting\Passkeys\Http\Resources\PasskeyResource;

final class RenamePasskeyController
{
    public function __invoke(RenamePasskeyRequest $request, RenamePasskey $rename, string $passkey): PasskeyResource
    {
        if (! ctype_digit($passkey)) {
            throw new PasskeyNotFound;
        }

        $guard = $request->guardConfig();

        return new PasskeyResource($rename->execute($guard->name(), RequestGuard::requireAccount($request, $guard), (int) $passkey, $request->toData()->name));
    }
}
