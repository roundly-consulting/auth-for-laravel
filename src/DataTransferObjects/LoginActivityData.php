<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;

final readonly class LoginActivityData
{
    public function __construct(
        public string $guard,
        public ActivityType $type,
        public ActivityOutcome $outcome,
        public SessionContext $context,
        public ?string $method = null,
        public ?string $reason = null,
        public ?Account $account = null,
        public ?string $identifier = null,
        public ?string $sessionId = null,
        public ?int $challengeId = null,
        public bool $newDevice = false,
    ) {}
}
