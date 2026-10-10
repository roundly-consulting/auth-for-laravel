<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * TOTP two-factor authentication was disabled for an account. `actor` is who disabled it
 * when it was not the account itself (`twoFactor()->disable(…, actor:)`).
 */
final readonly class TwoFactorDisabled
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ?Model $actor = null,
    ) {}
}
