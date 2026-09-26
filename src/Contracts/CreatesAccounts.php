<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Per-guard `registration.creator`: persists a new account (registration and
 * invitation acceptance).
 */
interface CreatesAccounts
{
    public function create(GuardConfig $guard, NewAccountData $data): Account;
}
