<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Events;

use Illuminate\Queue\SerializesModels;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account changed its locale/timezone.
 */
final readonly class LocaleUpdated
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public Account $account,
        public ?string $locale,
        public ?string $timezone,
    ) {}
}
