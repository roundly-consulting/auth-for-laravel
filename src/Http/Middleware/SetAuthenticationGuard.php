<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\RequestGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.guard:{guard}` — binds the guard a route serves to the request.
 */
final readonly class SetAuthenticationGuard
{
    public function __construct(private GuardRegistry $guards) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, string $guard): Response
    {
        $this->guards->get($guard);

        $request->attributes->set(RequestGuard::ATTRIBUTE, $guard);

        return $next($request);
    }
}
