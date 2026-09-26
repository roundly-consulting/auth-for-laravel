<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped;

use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Testing\Fixtures\Concerns\CountsCreations;

final class CustomOneTimeToken extends OneTimeToken
{
    use CountsCreations;
}
