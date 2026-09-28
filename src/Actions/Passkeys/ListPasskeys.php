<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passkeys;

use Illuminate\Support\Collection;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;

final readonly class ListPasskeys
{
    public function __construct(private GuardRegistry $guards) {}

    /**
     * @return Collection<int, Passkey>
     */
    public function execute(string $guard, Account $account): Collection
    {
        $this->guards->owning($guard, $account);

        return Passkeys::for(AccountModels::passkeys($account))->all()->values();
    }
}
