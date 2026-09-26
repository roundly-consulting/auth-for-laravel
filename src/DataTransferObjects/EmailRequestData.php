<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

final readonly class EmailRequestData
{
    public function __construct(
        public string $email,
        public SessionContext $context,
    ) {}
}
