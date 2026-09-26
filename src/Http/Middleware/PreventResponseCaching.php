<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.no-store` — token responses (RFC 6749 §5.1), challenge tokens, TOTP
 * secrets, recovery codes and passkey options must never be cached. Every package
 * route carries it.
 */
final class PreventResponseCaching
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
