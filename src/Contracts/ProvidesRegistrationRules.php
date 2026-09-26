<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Per-guard `registration.rules`: validation rules for the extra host fields of a
 * registration / invitation acceptance. Only the keys named here ever reach
 * {@see CreatesAccounts} — everything else is dropped.
 */
interface ProvidesRegistrationRules
{
    /**
     * @return array<string, mixed>
     */
    public function rules(GuardConfig $guard): array;
}
