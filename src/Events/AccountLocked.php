<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account was hard-locked (opt-in lockout, or an admin). `actor` is who locked it
 * (`lock(…, actor:)`); null for the automatic lockout or a lock without one.
 */
final readonly class AccountLocked
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public CarbonImmutable $until,
        public ?Model $actor = null,
    ) {}
}
