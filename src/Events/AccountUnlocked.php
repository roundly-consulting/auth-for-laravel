<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A locked account was unlocked. `actor` is who unlocked it (`unlock(…, actor:)`); null
 * without one.
 */
final readonly class AccountUnlocked
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ?Model $actor = null,
    ) {}
}
