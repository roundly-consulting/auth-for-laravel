<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use RoundlyConsulting\Auth\Actions\Account\DisableAccount;
use RoundlyConsulting\Auth\Actions\Account\EnableAccount;
use RoundlyConsulting\Auth\Actions\Account\LockAccount;
use RoundlyConsulting\Auth\Actions\Account\UnlockAccount;
use RoundlyConsulting\Auth\Actions\Account\UpdateLocale;
use RoundlyConsulting\Auth\Actions\Activity\ListLoginActivity;
use RoundlyConsulting\Auth\Actions\Login\AttemptPasswordLogin;
use RoundlyConsulting\Auth\Actions\Login\BeginPasskeyLogin;
use RoundlyConsulting\Auth\Actions\Login\CompletePasskeyLogin;
use RoundlyConsulting\Auth\Actions\Login\ConsumeMagicLink;
use RoundlyConsulting\Auth\Actions\Login\RequestEmailOtp;
use RoundlyConsulting\Auth\Actions\Login\RequestMagicLink;
use RoundlyConsulting\Auth\Actions\Login\VerifyEmailOtp;
use RoundlyConsulting\Auth\Actions\Registration\RegisterAccount;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Actions\Sessions\ListSessions;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutCurrentSession;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutEverywhere;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutOtherSessions;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutSession;
use RoundlyConsulting\Auth\Actions\Tokens\IssueAccountTokens;
use RoundlyConsulting\Auth\Actions\Tokens\RefreshTokenPair;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\SessionData;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\Contexts\ChallengesContext;
use RoundlyConsulting\Auth\Guards\Contexts\EmailContext;
use RoundlyConsulting\Auth\Guards\Contexts\InvitationsContext;
use RoundlyConsulting\Auth\Guards\Contexts\PasskeysContext;
use RoundlyConsulting\Auth\Guards\Contexts\PasswordsContext;
use RoundlyConsulting\Auth\Guards\Contexts\ReauthenticationContext;
use RoundlyConsulting\Auth\Guards\Contexts\ScopedToGuard;
use RoundlyConsulting\Auth\Guards\Contexts\TwoFactorContext;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use SensitiveParameter;

/**
 * One guard's API: the core verbs flat (login, registration, tokens, sessions, account
 * lifecycle) and a sub-context per area (`twoFactor()`, `passkeys()`, `passwords()`,
 * `email()`, `invitations()`, `reauthentication()`, `challenges()`). Every method runs
 * one action resolved from the container; every method taking an account refuses one of
 * another guard's model before anything is written ({@see AccountRepository::ensureOwns()}).
 *
 * ```php
 * $guard = Authentication::guard('clients');
 * $guard->attempt($credentials, $guard->contextFrom($request));
 * $guard->twoFactor()->status($client);
 * ```
 */
final readonly class GuardContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    public function name(): string
    {
        return $this->config->name();
    }

    public function config(): GuardConfig
    {
        return $this->config;
    }

    public function accounts(): AccountRepository
    {
        return new AccountRepository($this->config);
    }

    // ── Sub-areas ────────────────────────────────────────────────────────

    public function twoFactor(): TwoFactorContext
    {
        return new TwoFactorContext($this->config, $this->container);
    }

    public function passkeys(): PasskeysContext
    {
        return new PasskeysContext($this->config, $this->container);
    }

    public function passwords(): PasswordsContext
    {
        return new PasswordsContext($this->config, $this->container);
    }

    public function email(): EmailContext
    {
        return new EmailContext($this->config, $this->container);
    }

    public function invitations(): InvitationsContext
    {
        return new InvitationsContext($this->config, $this->container);
    }

    public function reauthentication(): ReauthenticationContext
    {
        return new ReauthenticationContext($this->config, $this->container);
    }

    public function challenges(): ChallengesContext
    {
        return new ChallengesContext($this->config, $this->container);
    }

    // ── Request-derived inputs ───────────────────────────────────────────

    /**
     * IP, user agent, device id/name, timezone and the negotiated locale of a request.
     */
    public function contextFrom(Request $request): SessionContext
    {
        return SessionContext::fromRequest($request, $this->config);
    }

    /**
     * The request's access token on this guard (`jti`, `sid`, `auth_time`, `amr`).
     *
     * @throws AuthenticationException when the request is not authenticated on the guard
     */
    public function tokenFrom(Request $request): CurrentToken
    {
        return CurrentToken::fromRequest($request, $this->config);
    }

    // ── Login ────────────────────────────────────────────────────────────

    public function attempt(PasswordCredentials $credentials, SessionContext $context): LoginResult
    {
        return $this->make(AttemptPasswordLogin::class)->execute($this->name(), $credentials, $context);
    }

    public function requestMagicLink(string $email, SessionContext $context): void
    {
        $this->make(RequestMagicLink::class)->execute($this->name(), $email, $context);
    }

    public function consumeMagicLink(#[SensitiveParameter] string $token, SessionContext $context): LoginResult
    {
        return $this->make(ConsumeMagicLink::class)->execute($this->name(), $token, $context);
    }

    public function requestEmailOtp(string $email, SessionContext $context): void
    {
        $this->make(RequestEmailOtp::class)->execute($this->name(), $email, $context);
    }

    public function verifyEmailOtp(string $email, #[SensitiveParameter] string $code, SessionContext $context): LoginResult
    {
        return $this->make(VerifyEmailOtp::class)->execute($this->name(), $email, $code, $context);
    }

    public function passkeyLoginOptions(SessionContext $context): RequestOptionsData
    {
        return $this->make(BeginPasskeyLogin::class)->execute($this->name(), $context);
    }

    public function loginWithPasskey(AuthenticationResponseData $response, SessionContext $context): LoginResult
    {
        return $this->make(CompletePasskeyLogin::class)->execute($this->name(), $response, $context);
    }

    // ── Registration ─────────────────────────────────────────────────────

    public function register(RegistrationData $data): RegistrationResult
    {
        return $this->make(RegisterAccount::class)->execute($this->name(), $data);
    }

    // ── Tokens & sessions ────────────────────────────────────────────────

    /**
     * Issue a pair from host code (impersonation, an SSO callback, tests) and announce it
     * (`TokensIssued`). The caller vouches for the authentication; `amr` defaults to none.
     *
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function issueTokens(Account $account, SessionContext $context, LoginMethod $method = LoginMethod::Host, array $authMethods = []): TokenPair
    {
        $this->own($account);

        return $this->make(IssueAccountTokens::class)->execute($this->name(), $account, $context, $method, $authMethods);
    }

    public function refresh(#[SensitiveParameter] string $refreshToken, SessionContext $context): TokenPair
    {
        return $this->make(RefreshTokenPair::class)->execute($this->name(), $refreshToken, $context);
    }

    /**
     * @return Collection<int, SessionData>
     */
    public function sessions(Account $account, ?string $currentSessionId = null): Collection
    {
        $this->own($account);

        return $this->make(ListSessions::class)->execute($this->name(), $account, $currentSessionId);
    }

    public function logout(Account $account, CurrentToken $current): void
    {
        $this->own($account);

        $this->make(LogoutCurrentSession::class)->execute($this->name(), $account, $current);
    }

    public function logoutSession(Account $account, string $sessionId): void
    {
        $this->own($account);

        $this->make(LogoutSession::class)->execute($this->name(), $account, $sessionId);
    }

    public function logoutOthers(Account $account, CurrentToken $current): int
    {
        $this->own($account);

        return $this->make(LogoutOtherSessions::class)->execute($this->name(), $account, $current);
    }

    public function logoutEverywhere(Account $account): int
    {
        $this->own($account);

        return $this->make(LogoutEverywhere::class)->execute($this->name(), $account);
    }

    /**
     * Apply the guard's invalidation policy for a reason; returns the pair re-issued to
     * `$keep`'s device under `others` (null otherwise).
     */
    public function invalidate(Account $account, InvalidationReason $reason, ?CurrentToken $keep = null, ?SessionContext $context = null): ?TokenPair
    {
        $this->own($account);

        return $this->make(InvalidateAccountTokens::class)
            ->execute($this->config, $account, $reason, $keep, $context ?? new SessionContext)
            ->tokens;
    }

    // ── Account ──────────────────────────────────────────────────────────

    public function disable(Account $account, ?string $reason = null): void
    {
        $this->own($account);

        $this->make(DisableAccount::class)->execute($this->name(), $account, $reason);
    }

    public function enable(Account $account): void
    {
        $this->own($account);

        $this->make(EnableAccount::class)->execute($this->name(), $account);
    }

    /**
     * Hard-lock the account (default `lockout.duration`) and tell its owner; sessions stay.
     */
    public function lock(Account $account, ?int $seconds = null): CarbonImmutable
    {
        $this->own($account);

        return $this->make(LockAccount::class)->execute($this->name(), $account, $seconds);
    }

    public function unlock(Account $account): void
    {
        $this->own($account);

        $this->make(UnlockAccount::class)->execute($this->name(), $account);
    }

    /**
     * Set the notification locale and/or display timezone (only the fields `$data` flags).
     */
    public function updateLocale(Account $account, LocaleData $data): Account
    {
        $this->own($account);

        return $this->make(UpdateLocale::class)->execute($this->name(), $account, $data);
    }

    /**
     * The account's own login activity on this guard, newest first.
     *
     * @return LengthAwarePaginator<int, LoginActivity>
     */
    public function activity(Account $account, int $perPage = 20): LengthAwarePaginator
    {
        $this->own($account);

        return $this->make(ListLoginActivity::class)->execute($this->name(), $account, $perPage);
    }
}
