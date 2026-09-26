<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped;

use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Testing\Fixtures\Concerns\CountsCreations;

final class CustomLoginChallenge extends LoginChallenge
{
    use CountsCreations;
}
