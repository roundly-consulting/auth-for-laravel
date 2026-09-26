<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

interface ChecksBreachedPasswords
{
    public function isBreached(#[SensitiveParameter] string $password, GuardConfig $guard): bool;
}
