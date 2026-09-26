<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

final readonly class LocaleData
{
    public function __construct(
        public ?string $locale,
        public ?string $timezone,
    ) {}
}
