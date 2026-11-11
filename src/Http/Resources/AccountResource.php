<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * The `me` payload. Swap it per guard with `resources.account`. Not final: a documented
 * extension point.
 *
 * @property Account $resource
 */
class AccountResource extends JsonResource
{
    /**
     * @return array{id: mixed, email: string|null, email_verified: bool, locale: string|null, timezone: string|null}
     */
    public function toArray(Request $request): array
    {
        $account = $this->account();

        return [
            'id' => $account->getAuthIdentifier(),
            'email' => $account->accountEmail(),
            'email_verified' => $account->hasVerifiedEmail(),
            'locale' => $account->accountLocale(),
            'timezone' => $account->accountTimezone(),
        ];
    }

    /**
     * The wrapped account, typed by its contract.
     */
    protected function account(): Account
    {
        return $this->resource;
    }
}
