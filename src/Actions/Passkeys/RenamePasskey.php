<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passkeys;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Exceptions\PasskeyNotFound;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Renames one of the account's passkeys (cosmetic). A foreign or unknown id is a 404.
 */
final readonly class RenamePasskey
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, int $passkeyId, string $name): Passkey
    {
        $this->guards->get($guard);

        $model = AccountModels::passkeys($account);
        $passkey = $model->passkeys()->whereKey($passkeyId)->first();

        if (! $passkey instanceof Passkey) {
            throw new PasskeyNotFound;
        }

        return Passkeys::for($model)->rename($passkey, (string) SessionContext::clean($name));
    }
}
