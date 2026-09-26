<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LogoutScope;

/**
 * One or more sessions were ended by a logout.
 */
final readonly class LoggedOut
{
    public function __construct(
        public string $guard,
        public Account $account,
        public LogoutScope $scope,
        public int $revoked,
    ) {}
}
