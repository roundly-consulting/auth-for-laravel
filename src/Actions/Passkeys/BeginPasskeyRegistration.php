<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passkeys;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

final readonly class BeginPasskeyRegistration
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account): CreationOptionsData
    {
        if ($this->guards->owning($guard, $account)->passkeyMode() === PasskeyMode::Off) {
            throw new LoginMethodDisabled;
        }

        return Passkeys::for(AccountModels::passkeys($account))->registrationOptions();
    }
}
