<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account was disabled. `actor` is who disabled it (`disable(…, actor:)`); null
 * without one.
 */
final readonly class AccountDisabled
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ?string $reason,
        public ?Model $actor = null,
    ) {}
}
