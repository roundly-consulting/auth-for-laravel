<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A password was changed (or set by the host/an admin). `actor` is who set it when it was
 * not the account itself (`passwords()->set(…, actor:)`); null for the account's own
 * change or reset.
 */
final readonly class PasswordChanged
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ?Model $actor = null,
    ) {}
}
