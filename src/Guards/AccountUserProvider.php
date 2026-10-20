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
 * access token of a just-disabled account authenticates nobody — and that credentials
 * are looked up only as non-empty strings.
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
     * Every credential but the password must be a non-empty string under a column name;
     * anything else matches nobody and sends no query. Laravel's `token` guard before
     * 12.68 / 13.29 (GHSA-f9x3-7vq9-cph6) passed request arrays straight through, and
     * MySQL matches `email IN (0)` against every letter-first address.
     *
     * @param  array<array-key, mixed>  $credentials
     */
    public function retrieveByCredentials(#[SensitiveParameter] array $credentials): ?Authenticatable
    {
        foreach ($credentials as $key => $value) {
            if (is_string($key) && str_contains($key, 'password')) {
                continue;
            }

            if (! is_string($key) || ! is_string($value) || $value === '') {
                return null;
            }
        }

        $account = parent::retrieveByCredentials($credentials);

        return $account instanceof Account && ! $account->isDisabled() ? $account : null;
    }

    /**
     * A password that is not a string never validates (and never reaches the hasher).
     *
     * @param  array<array-key, mixed>  $credentials
     */
    public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
    {
        if (! is_string($credentials['password'] ?? null)) {
            return false;
        }

        return parent::validateCredentials($user, $credentials);
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
