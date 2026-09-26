<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use RoundlyConsulting\Auth\Contracts\NegotiatesLocale;
use RoundlyConsulting\Auth\Http\RequestGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.locale[:guard]` — applies the account's locale, else the negotiated
 * one, else leaves the app default.
 */
final readonly class ApplyAccountLocale
{
    public function __construct(private NegotiatesLocale $negotiator) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $config = RequestGuard::config($request, $guard);
        $locale = RequestGuard::account($request, $config)?->accountLocale() ?? $this->negotiator->negotiate($request, $config);

        if ($locale !== null) {
            App::setLocale($locale);
        }

        return $next($request);
    }
}
