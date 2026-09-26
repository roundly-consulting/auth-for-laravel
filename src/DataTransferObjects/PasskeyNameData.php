<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

final readonly class PasskeyNameData
{
    public function __construct(public string $name) {}
}
