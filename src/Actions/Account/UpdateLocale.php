<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\Events\LocaleUpdated;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Rules\SupportedLocale;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Sets the account's notification locale and (when the guard keeps them) its display
 * timezone — only the fields the change carries; the other keeps its stored value.
 * Persisted times stay in the app timezone; the user's is display-only.
 */
final readonly class UpdateLocale
{
    public function __construct(private GuardRegistry $guards) {}

    public function execute(string $guard, Account $account, LocaleData $data): Account
    {
        $config = $this->guards->owning($guard, $account);

        Validator::make(
            ['locale' => $data->locale, 'timezone' => $data->timezone],
            [
                'locale' => ['nullable', 'string', new SupportedLocale($config)],
                'timezone' => ['nullable', 'string', 'timezone:all'],
            ],
        )->validate();

        $changes = [];

        if ($data->updatesLocale) {
            $changes[Columns::locale()] = $data->locale;
        }

        if ($data->updatesTimezone || ! $config->timezonesEnabled()) {
            $changes[Columns::timezone()] = $config->timezonesEnabled() ? $data->timezone : null;
        }

        if ($changes !== []) {
            AccountState::write($account, $changes);
        }

        event(new LocaleUpdated($guard, $account, $account->accountLocale(), $account->accountTimezone()));

        return $account;
    }
}
