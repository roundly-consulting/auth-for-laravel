<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Support;

use Illuminate\Auth\TokenGuard;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Laravel's `token` guard as shipped before GHSA-f9x3-7vq9-cph6 (laravel/framework < 12.68 /
 * < 13.29): `user()` passes any non-empty input — an array included — to the provider's
 * `retrieveByCredentials()`. A host on an old framework still runs this code.
 */
final class PreFixTokenGuard extends TokenGuard
{
    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $user = null;
        $token = $this->getTokenForRequest();

        if (! empty($token)) {
            $user = $this->provider->retrieveByCredentials([
                $this->storageKey => $this->hash ? hash('sha256', $token) : $token,
            ]);
        }

        return $this->user = $user;
    }
}
