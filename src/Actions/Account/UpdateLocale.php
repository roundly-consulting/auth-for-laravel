<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Events\LocaleUpdated;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Rules\SupportedLocale;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Sets the account's notification locale and (when the guard keeps them) its display
 * timezone. Persisted times stay in the app timezone; the user's is display-only.
 */
final readonly class UpdateLocale
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, ?string $locale, ?string $timezone): Account
    {
        $config = $this->guards->get($guard);

        Validator::make(
            ['locale' => $locale, 'timezone' => $timezone],
            [
                'locale' => ['nullable', 'string', new SupportedLocale($config)],
                'timezone' => ['nullable', 'string', 'timezone:all'],
            ],
        )->validate();

        AccountState::write($account, [
            Columns::locale() => $locale,
            Columns::timezone() => $config->timezonesEnabled() ? $timezone : null,
        ]);

        event(new LocaleUpdated($guard, $account, $locale, $config->timezonesEnabled() ? $timezone : null));

        return $account;
    }
}
