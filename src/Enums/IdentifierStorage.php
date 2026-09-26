<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How the typed login identifier is kept in activity rows.
 */
enum IdentifierStorage: string
{
    use Helpers;

    case Plain = 'plain';
    case Hash = 'hash';
    case None = 'none';
}
