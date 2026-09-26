<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Registration;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\CreatesAccounts;
use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * The default account creator: the normalised email, a hashed password (or none),
 * locale/timezone, verification state, and the host's extra attributes — which the
 * caller has already allow-listed by the host's registration rules. Never raw input.
 */
final readonly class CreateAccount implements CreatesAccounts
{
    public function __construct(private Hasher $hasher) {}

    public function create(GuardConfig $guard, NewAccountData $data): Account
    {
        $accounts = new AccountRepository($guard);
        $account = $accounts->newModel();
        $now = CarbonImmutable::now();

        $account->forceFill([
            ...$data->attributes,
            $guard->emailColumn() => $accounts->normalizeEmail($data->email),
            Columns::password() => $data->password === null ? null : $this->hasher->make($data->password),
            Columns::passwordChangedAt() => $data->password === null ? null : $now,
            Columns::emailVerifiedAt() => $data->emailVerified ? $now : null,
            Columns::locale() => $data->locale,
            Columns::timezone() => $guard->timezonesEnabled() ? $data->timezone : null,
        ])->save();

        return $account;
    }
}
