<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Container\Container;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Collection;
use RoundlyConsulting\Auth\Actions\Activity\PruneAuthenticationData;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PruneReport;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\SessionData;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\Contexts\ChallengesContext;
use RoundlyConsulting\Auth\Guards\Contexts\EmailContext;
use RoundlyConsulting\Auth\Guards\Contexts\InvitationsContext;
use RoundlyConsulting\Auth\Guards\Contexts\PasskeysContext;
use RoundlyConsulting\Auth\Guards\Contexts\PasswordsContext;
use RoundlyConsulting\Auth\Guards\Contexts\ReauthenticationContext;
use RoundlyConsulting\Auth\Guards\Contexts\TwoFactorContext;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardContext;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Http\RouteRegistrar;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use SensitiveParameter;

/**
 * The root behind the {@see Facades\Authentication} facade — inject it for the same API
 * without the facade. `guard($name)` is one guard's API; every other per-guard method
 * here is that same call on the DEFAULT guard (`authentication.default`), so
 * `Authentication::twoFactor()->status($user)` ≡ `Authentication::guard()->twoFactor()->status($user)`.
 *
 * A singleton that holds no container: it resolves the ACTIVE one on every call, so
 * under Octane (each request runs in a clone of the booted app) it reads the current
 * request and hands guard contexts the request's container, not the boot-time one.
 */
final class AuthenticationManager
{
    /** @var array<string, true> */
    private array $routedGuards = [];

    /**
     * One guard's API (null → `authentication.default`).
     */
    public function guard(?string $name = null): GuardContext
    {
        return new GuardContext($this->registry()->get($name), $this->app());
    }

    /**
     * @return list<string>
     */
    public function guards(): array
    {
        return $this->registry()->names();
    }

    /**
     * Register a guard's JSON endpoints (fluent; registers on destruct).
     */
    public function routes(string $guard): RouteRegistrar
    {
        $config = $this->registry()->get($guard);

        if (isset($this->routedGuards[$config->name()])) {
            throw AuthenticationMisconfigured::routesAlreadyRegistered($config->name());
        }

        return new RouteRegistrar($this->app()->make(Router::class), $config, $this);
    }

    /**
     * The guard the current request's package route serves, if any.
     */
    public function currentGuard(): ?GuardContext
    {
        $app = $this->app();

        if (! $app->bound('request')) {
            return null;
        }

        $guard = $app->make('request')->attributes->get(RequestGuard::ATTRIBUTE);

        return is_string($guard) ? $this->guard($guard) : null;
    }

    /**
     * @internal called by the registrar; a second registration for a guard is a misconfiguration.
     */
    public function markRoutesRegistered(string $guard): void
    {
        if (isset($this->routedGuards[$guard])) {
            throw AuthenticationMisconfigured::routesAlreadyRegistered($guard);
        }

        $this->routedGuards[$guard] = true;
    }

    public function routesRegistered(string $guard): bool
    {
        return isset($this->routedGuards[$guard]);
    }

    /**
     * Delete expired challenges and one-time tokens, and finished invitations and activity
     * rows past their guard's retention (or `$days`) — every guard.
     */
    public function prune(?int $days = null): PruneReport
    {
        return $this->app()->make(PruneAuthenticationData::class)->execute($days);
    }

    // ── The default guard ────────────────────────────────────────────────

    public function name(): string
    {
        return $this->guard()->name();
    }

    public function config(): GuardConfig
    {
        return $this->guard()->config();
    }

    public function accounts(): AccountRepository
    {
        return $this->guard()->accounts();
    }

    public function twoFactor(): TwoFactorContext
    {
        return $this->guard()->twoFactor();
    }

    public function passkeys(): PasskeysContext
    {
        return $this->guard()->passkeys();
    }

    public function passwords(): PasswordsContext
    {
        return $this->guard()->passwords();
    }

    public function email(): EmailContext
    {
        return $this->guard()->email();
    }

    public function invitations(): InvitationsContext
    {
        return $this->guard()->invitations();
    }

    public function reauthentication(): ReauthenticationContext
    {
        return $this->guard()->reauthentication();
    }

    public function challenges(): ChallengesContext
    {
        return $this->guard()->challenges();
    }

    public function contextFrom(Request $request): SessionContext
    {
        return $this->guard()->contextFrom($request);
    }

    /**
     * @throws AuthenticationException
     */
    public function tokenFrom(Request $request): CurrentToken
    {
        return $this->guard()->tokenFrom($request);
    }

    public function attempt(PasswordCredentials $credentials, SessionContext $context): LoginResult
    {
        return $this->guard()->attempt($credentials, $context);
    }

    public function requestMagicLink(string $email, SessionContext $context): void
    {
        $this->guard()->requestMagicLink($email, $context);
    }

    public function consumeMagicLink(#[SensitiveParameter] string $token, SessionContext $context): LoginResult
    {
        return $this->guard()->consumeMagicLink($token, $context);
    }

    public function requestEmailOtp(string $email, SessionContext $context): void
    {
        $this->guard()->requestEmailOtp($email, $context);
    }

    public function verifyEmailOtp(string $email, #[SensitiveParameter] string $code, SessionContext $context): LoginResult
    {
        return $this->guard()->verifyEmailOtp($email, $code, $context);
    }

    public function passkeyLoginOptions(SessionContext $context): RequestOptionsData
    {
        return $this->guard()->passkeyLoginOptions($context);
    }

    public function loginWithPasskey(AuthenticationResponseData $response, SessionContext $context): LoginResult
    {
        return $this->guard()->loginWithPasskey($response, $context);
    }

    public function register(RegistrationData $data): RegistrationResult
    {
        return $this->guard()->register($data);
    }

    /**
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function issueTokens(Account $account, SessionContext $context, LoginMethod $method = LoginMethod::Host, array $authMethods = []): TokenPair
    {
        return $this->guard()->issueTokens($account, $context, $method, $authMethods);
    }

    public function refresh(#[SensitiveParameter] string $refreshToken, SessionContext $context): TokenPair
    {
        return $this->guard()->refresh($refreshToken, $context);
    }

    /**
     * @return Collection<int, SessionData>
     */
    public function sessions(Account $account, ?string $currentSessionId = null): Collection
    {
        return $this->guard()->sessions($account, $currentSessionId);
    }

    public function logout(Account $account, CurrentToken $current): void
    {
        $this->guard()->logout($account, $current);
    }

    public function logoutSession(Account $account, string $sessionId): void
    {
        $this->guard()->logoutSession($account, $sessionId);
    }

    public function logoutOthers(Account $account, CurrentToken $current): int
    {
        return $this->guard()->logoutOthers($account, $current);
    }

    public function logoutEverywhere(Account $account): int
    {
        return $this->guard()->logoutEverywhere($account);
    }

    public function invalidate(Account $account, InvalidationReason $reason, ?CurrentToken $keep = null, ?SessionContext $context = null): ?TokenPair
    {
        return $this->guard()->invalidate($account, $reason, $keep, $context);
    }

    public function disable(Account $account, ?string $reason = null): void
    {
        $this->guard()->disable($account, $reason);
    }

    public function enable(Account $account): void
    {
        $this->guard()->enable($account);
    }

    public function lock(Account $account, ?int $seconds = null): CarbonImmutable
    {
        return $this->guard()->lock($account, $seconds);
    }

    public function unlock(Account $account): void
    {
        $this->guard()->unlock($account);
    }

    public function updateLocale(Account $account, LocaleData $data): Account
    {
        return $this->guard()->updateLocale($account, $data);
    }

    /**
     * @return LengthAwarePaginator<int, LoginActivity>
     */
    public function activity(Account $account, int $perPage = 20): LengthAwarePaginator
    {
        return $this->guard()->activity($account, $perPage);
    }

    private function registry(): GuardRegistry
    {
        return $this->app()->make(GuardRegistry::class);
    }

    private function app(): Container
    {
        return Container::getInstance();
    }
}
