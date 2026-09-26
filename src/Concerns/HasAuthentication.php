<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Concerns;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Columns;

/**
 * Implements {@see Account} for an Eloquent guard model through the configurable
 * `authentication.columns.*`. Spread {@see self::authenticationCasts()} into the model's
 * `casts()`:
 *
 * ```php
 * protected function casts(): array
 * {
 *     return [...$this->authenticationCasts(), ...$this->twoFactorCasts(), 'email_verified_at' => 'datetime'];
 * }
 * ```
 *
 * `preferredLocale()` makes Laravel localise the account's notifications automatically.
 *
 * @phpstan-require-extends Model
 *
 * @phpstan-require-implements Account
 */
trait HasAuthentication
{
    public function initializeHasAuthentication(): void
    {
        $this->makeHidden([
            Columns::tokenVersion(),
            Columns::lockedUntil(),
            Columns::disabledReason(),
            Columns::failedLoginCount(),
        ]);
    }

    /**
     * @return array<string, string>
     */
    public function authenticationCasts(): array
    {
        return [
            Columns::tokenVersion() => 'integer',
            Columns::failedLoginCount() => 'integer',
            Columns::passwordChangedAt() => 'immutable_datetime',
            Columns::lastLoginAt() => 'immutable_datetime',
            Columns::disabledAt() => 'immutable_datetime',
            Columns::lockedUntil() => 'immutable_datetime',
        ];
    }

    /**
     * The column holding this account's email: the owning guard's
     * `identifier.email_column`, or `email`.
     */
    public function accountEmailColumn(): string
    {
        return app(GuardRegistry::class)->forModel($this)?->emailColumn() ?? 'email';
    }

    public function accountEmail(): ?string
    {
        $email = $this->getAttribute($this->accountEmailColumn());

        return is_string($email) && $email !== '' ? $email : null;
    }

    public function hasPassword(): bool
    {
        $password = $this->getAttribute(Columns::password());

        return is_string($password) && $password !== '';
    }

    public function hasVerifiedEmail(): bool
    {
        return $this->getAttribute(Columns::emailVerifiedAt()) !== null;
    }

    public function markEmailAsVerified(): bool
    {
        return $this->forceFill([Columns::emailVerifiedAt() => $this->freshTimestamp()])->saveQuietly();
    }

    public function tokenVersion(): int
    {
        return (int) $this->getAttribute(Columns::tokenVersion());
    }

    public function isDisabled(): bool
    {
        return $this->getAttribute(Columns::disabledAt()) !== null;
    }

    public function isLocked(): bool
    {
        $until = $this->lockedUntil();

        return $until !== null && $until->isFuture();
    }

    public function lockedUntil(): ?CarbonImmutable
    {
        $until = $this->getAttribute(Columns::lockedUntil());

        return $until instanceof CarbonInterface ? CarbonImmutable::instance($until) : null;
    }

    public function accountLocale(): ?string
    {
        $locale = $this->getAttribute(Columns::locale());

        return is_string($locale) && $locale !== '' ? $locale : null;
    }

    public function accountTimezone(): ?string
    {
        $timezone = $this->getAttribute(Columns::timezone());

        return is_string($timezone) && $timezone !== '' ? $timezone : null;
    }

    /**
     * Laravel's notification sender localises mail with this automatically.
     */
    public function preferredLocale(): ?string
    {
        return $this->accountLocale();
    }
}
