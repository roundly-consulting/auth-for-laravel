<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped;

use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Testing\Fixtures\Concerns\CountsCreations;

final class CustomLoginActivity extends LoginActivity
{
    use CountsCreations;
}
