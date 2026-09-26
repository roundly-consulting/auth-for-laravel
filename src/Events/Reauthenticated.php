<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;

/**
 * An authenticated account re-proved itself for sensitive actions.
 */
final readonly class Reauthenticated
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ReauthenticationMethod $method,
    ) {}
}
