<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Translation\HasLocalePreference;
use RoundlyConsulting\Auth\Concerns\HasAuthentication;

/**
 * Implemented by every guard model — use {@see HasAuthentication}.
 */
interface Account extends Authenticatable, HasLocalePreference
{
    public function accountEmail(): ?string;

    public function hasPassword(): bool;

    /** Same name as Laravel's MustVerifyEmail on purpose. */
    public function hasVerifiedEmail(): bool;

    /** Same name as Laravel's MustVerifyEmail on purpose. */
    public function markEmailAsVerified(): bool;

    public function tokenVersion(): int;

    public function isDisabled(): bool;

    /** `locked_until` lies in the future. */
    public function isLocked(): bool;

    public function accountLocale(): ?string;

    public function accountTimezone(): ?string;
}
