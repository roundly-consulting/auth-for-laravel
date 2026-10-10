<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * A passkey was removed from an account. `actor` is who removed it when it was not the
 * account itself (`passkeys()->remove(…, actor:)`).
 */
final readonly class PasskeyRemoved
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public int $passkeyId,
        public ?Model $actor = null,
    ) {}
}
