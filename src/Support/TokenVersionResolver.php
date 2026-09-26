<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * The `token_version` resolver every jwt guard used by this package must be configured
 * with (`jwt.guard.token_version` or `auth.guards.<g>.token_version`). An invokable
 * class rather than a closure, because closures break `config:cache`. Without it a
 * `tv++` revokes nothing.
 */
final class TokenVersionResolver
{
    public function __invoke(Authenticatable $account): int
    {
        return $account instanceof Account ? $account->tokenVersion() : 0;
    }
}
