<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * A login risk assessment.
 */
enum RiskLevel: string
{
    use Helpers;

    case Low = 'low';
    case Elevated = 'elevated';
    case High = 'high';
}
