<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped;

use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Testing\Fixtures\Concerns\CountsCreations;

final class CustomInvitation extends Invitation
{
    use CountsCreations;
}
