<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A disabled account was enabled again. `actor` is who enabled it (`enable(…, actor:)`);
 * null without one.
 */
final readonly class AccountEnabled
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ?Model $actor = null,
    ) {}
}
