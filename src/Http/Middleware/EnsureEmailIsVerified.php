<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Exceptions\EmailNotVerified;
use RoundlyConsulting\Auth\Http\RequestGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.verified[:guard]` — 403 `email_not_verified` when the guard requires a
 * verified address (for actions or for login) and the account has none. Reads the
 * account row, never the token claim, so it is never stale.
 */
final class EnsureEmailIsVerified
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $config = RequestGuard::config($request, $guard);
        $account = RequestGuard::account($request, $config);

        $enforced = in_array($config->verificationMode(), [EmailVerificationMode::RequiredForActions, EmailVerificationMode::RequiredForLogin], true);

        if ($enforced && $account !== null && ! $account->hasVerifiedEmail()) {
            throw new EmailNotVerified;
        }

        return $next($request);
    }
}
