<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Support;

use RoundlyConsulting\Auth\Contracts\ProvidesRegistrationRules;
use RoundlyConsulting\Auth\Guards\GuardConfig;

final class NestedProfileRules implements ProvidesRegistrationRules
{
    public function rules(GuardConfig $guard): array
    {
        return [
            'name' => ['required', 'string'],
            'profile.city' => ['required', 'string'],
            'tags.*' => ['string'],
        ];
    }
}
