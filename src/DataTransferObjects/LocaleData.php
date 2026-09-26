<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

/**
 * A locale/timezone change. Only the fields flagged as sent are written: a field the
 * client left out keeps its stored value, one sent as null is cleared.
 */
final readonly class LocaleData
{
    public function __construct(
        public ?string $locale = null,
        public ?string $timezone = null,
        public bool $updatesLocale = true,
        public bool $updatesTimezone = true,
    ) {}
}
