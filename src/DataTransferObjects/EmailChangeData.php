<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

final readonly class EmailChangeData
{
    public function __construct(
        public string $newEmail,
        public SessionContext $context,
    ) {}
}
