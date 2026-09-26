<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account changed its locale/timezone.
 */
final readonly class LocaleUpdated
{
    public function __construct(
        public string $guard,
        public Account $account,
        public ?string $locale,
        public ?string $timezone,
    ) {}
}
