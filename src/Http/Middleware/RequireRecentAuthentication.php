<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Actions\Account\EnsureRecentlyAuthenticated;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Http\RequestGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.reauthenticated[:seconds[,guard]]` — 403 `reauthentication_required`
 * unless the calling session re-authenticated within the window with a proof the
 * account's current factors accept (see {@see EnsureRecentlyAuthenticated}).
 */
final readonly class RequireRecentAuthentication
{
    public function __construct(private EnsureRecentlyAuthenticated $ensureRecent) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $seconds = null, ?string $guard = null): Response
    {
        $config = RequestGuard::config($request, $guard);

        $this->ensureRecent->execute(
            $config->name(),
            CurrentToken::fromRequest($request, $config),
            RequestGuard::requireAccount($request, $config),
            $seconds !== null && ctype_digit($seconds) ? (int) $seconds : null,
        );

        return $next($request);
    }
}
