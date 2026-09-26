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
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $account = $this->resource;

        return [
            'id' => $account->getAuthIdentifier(),
            'email' => $account->accountEmail(),
            'email_verified' => $account->hasVerifiedEmail(),
            'locale' => $account->accountLocale(),
            'timezone' => $account->accountTimezone(),
        ];
    }
}
