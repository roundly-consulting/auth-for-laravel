<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\LoginMethod;

/**
 * An email login (magic link or email code) verified an unverified address with
 * `verification.secure_on_email_login` on, so everything set on the account before the
 * address was proven was discarded: the password, the two-factor enrolment, the passkeys,
 * every session and refresh token and every pending one-time secret. Whoever registered the
 * address before its owner did (account pre-hijacking) keeps no way in.
 */
final readonly class AccountClaimed
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public LoginMethod $method,
        public bool $passwordRemoved,
        public bool $twoFactorRemoved,
        public int $passkeysRemoved,
        public int $sessionsRevoked,
    ) {}
}
