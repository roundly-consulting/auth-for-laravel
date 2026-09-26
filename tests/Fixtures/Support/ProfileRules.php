<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Support;

use RoundlyConsulting\Auth\Contracts\ProvidesRegistrationRules;
use RoundlyConsulting\Auth\Guards\GuardConfig;

final class ProfileRules implements ProvidesRegistrationRules
{
    public function rules(GuardConfig $guard): array
    {
        return ['name' => ['required', 'string', 'max:100']];
    }
}
