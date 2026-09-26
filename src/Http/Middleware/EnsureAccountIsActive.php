<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Exceptions\AccountDisabled;
use RoundlyConsulting\Auth\Http\RequestGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.active[:guard]` — 403 for a disabled account (belt-and-braces over the
 * `tv` bump and the provider, for hosts that resolve accounts another way).
 */
final class EnsureAccountIsActive
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        if (RequestGuard::account($request, RequestGuard::config($request, $guard))?->isDisabled() === true) {
            throw new AccountDisabled;
        }

        return $next($request);
    }
}
