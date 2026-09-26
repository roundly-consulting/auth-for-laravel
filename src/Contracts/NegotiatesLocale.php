<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Contracts;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Guards\GuardConfig;

interface NegotiatesLocale
{
    /**
     * The best supported locale for the request, or null when none matches.
     */
    public function negotiate(Request $request, GuardConfig $guard): ?string;
}
