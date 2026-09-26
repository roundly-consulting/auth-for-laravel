<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What a guard does about an assessed login risk.
 */
enum RiskReaction: string
{
    use Helpers;

    case Allow = 'allow';
    case Notify = 'notify';
    case RequireSecondFactor = 'require_second_factor';
    case Deny = 'deny';
}
