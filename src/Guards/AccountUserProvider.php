<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use RoundlyConsulting\Auth\Contracts\Account;
use SensitiveParameter;

/**
 * The `authentication` user-provider driver: Eloquent over the guard's model, except
 * that a disabled account (or a soft-deleted one) never resolves — so a still-valid
 * access token of a just-disabled account authenticates nobody.
 *
 * ```php
 * 'providers' => ['clients' => ['driver' => 'authentication', 'guard' => 'clients']],
 * ```
 */
final class AccountUserProvider extends EloquentUserProvider
{
    public function __construct(Hasher $hasher, private readonly GuardConfig $guard)
    {
        parent::__construct($hasher, $guard->model());
    }

    public function guard(): GuardConfig
    {
        return $this->guard;
    }

    public function retrieveById($identifier): ?Authenticatable
    {
        $account = parent::retrieveById($identifier);

        return $account instanceof Account && ! $account->isDisabled() ? $account : null;
    }

    /**
     * Stateless bearer authentication has no remember-me tokens.
     */
    public function retrieveByToken($identifier, #[SensitiveParameter] $token): ?Authenticatable
    {
        return null;
    }

    public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] $token): void {}
}
