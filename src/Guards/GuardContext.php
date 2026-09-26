<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use RoundlyConsulting\Auth\Actions\Account\DisableAccount;
use RoundlyConsulting\Auth\Actions\Account\EnableAccount;
use RoundlyConsulting\Auth\Actions\Account\UnlockAccount;
use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyEnrolmentStep;
use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyStep;
use RoundlyConsulting\Auth\Actions\Challenges\CompleteTwoFactorStep;
use RoundlyConsulting\Auth\Actions\Challenges\ConfirmTwoFactorEnrolmentStep;
use RoundlyConsulting\Auth\Actions\Invitations\AcceptInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\CreateInvitation;
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
use RoundlyConsulting\Auth\Actions\Tokens\IssueTokenPair;
use RoundlyConsulting\Auth\Actions\Tokens\RefreshTokenPair;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\SessionData;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use SensitiveParameter;

/**
 * The per-guard, discoverable surface: every method is one action call. A method taking
 * an account refuses one of another guard's model ({@see AccountRepository::ensureOwns()}).
 *
 * ```php
 * Authentication::guard('clients')->attempt($credentials, SessionContext::fromRequest($request));
 * ```
 */
final readonly class GuardContext
{
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

    // ── Login ────────────────────────────────────────────────────────────

    public function attempt(PasswordCredentials $credentials, SessionContext $context): LoginResult
    {
        return $this->container->make(AttemptPasswordLogin::class)->execute($this->name(), $credentials, $context);
    }

    public function requestMagicLink(string $email, SessionContext $context): void
    {
        $this->container->make(RequestMagicLink::class)->execute($this->name(), $email, $context);
    }

    public function consumeMagicLink(#[SensitiveParameter] string $token, SessionContext $context): LoginResult
    {
        return $this->container->make(ConsumeMagicLink::class)->execute($this->name(), $token, $context);
    }

    public function requestEmailOtp(string $email, SessionContext $context): void
    {
        $this->container->make(RequestEmailOtp::class)->execute($this->name(), $email, $context);
    }

    public function verifyEmailOtp(string $email, #[SensitiveParameter] string $code, SessionContext $context): LoginResult
    {
        return $this->container->make(VerifyEmailOtp::class)->execute($this->name(), $email, $code, $context);
    }

    public function passkeyLoginOptions(SessionContext $context): RequestOptionsData
    {
        return $this->container->make(BeginPasskeyLogin::class)->execute($this->name(), $context);
    }

    public function loginWithPasskey(AuthenticationResponseData $response, SessionContext $context): LoginResult
    {
        return $this->container->make(CompletePasskeyLogin::class)->execute($this->name(), $response, $context);
    }

    /**
     * Continue a pending challenge with a TOTP / recovery code, an enrolment
     * confirmation, a passkey assertion or a passkey registration.
     */
    public function completeChallenge(ChallengeFactorData $data): LoginResult
    {
        $action = match ($data->method) {
            FactorMethod::Totp, FactorMethod::RecoveryCode => CompleteTwoFactorStep::class,
            FactorMethod::TotpEnrolment => ConfirmTwoFactorEnrolmentStep::class,
            FactorMethod::Passkey => CompletePasskeyStep::class,
            FactorMethod::PasskeyEnrolment => CompletePasskeyEnrolmentStep::class,
        };

        return $this->container->make($action)->execute($this->name(), $data);
    }

    // ── Registration & invitations ───────────────────────────────────────

    public function register(RegistrationData $data): RegistrationResult
    {
        return $this->container->make(RegisterAccount::class)->execute($this->name(), $data);
    }

    public function invite(InvitationData $data): Invitation
    {
        return $this->container->make(CreateInvitation::class)->execute($this->name(), $data);
    }

    public function acceptInvitation(AcceptInvitationData $data): LoginResult
    {
        return $this->container->make(AcceptInvitation::class)->execute($this->name(), $data);
    }

    // ── Tokens & sessions ────────────────────────────────────────────────

    /**
     * Issue a pair from host code (impersonation, an SSO callback, tests). The caller
     * vouches for the authentication; `amr` defaults to none.
     *
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function issueTokens(Account $account, SessionContext $context, LoginMethod $method = LoginMethod::Host, array $authMethods = []): TokenPair
    {
        $this->own($account);

        $tokens = $this->container->make(IssueTokenPair::class)->execute($this->config, $account, $method, $authMethods, $context);

        event(new TokensIssued($this->name(), $account, $tokens->sessionId, $tokens->accessTokenId, $method));

        return $tokens;
    }

    public function refresh(#[SensitiveParameter] string $refreshToken, SessionContext $context): TokenPair
    {
        return $this->container->make(RefreshTokenPair::class)->execute($this->name(), $refreshToken, $context);
    }

    /**
     * @return Collection<int, SessionData>
     */
    public function sessions(Account $account, ?string $currentSessionId = null): Collection
    {
        $this->own($account);

        return $this->container->make(ListSessions::class)->execute($this->name(), $account, $currentSessionId);
    }

    public function logout(Account $account, CurrentToken $current): void
    {
        $this->own($account);

        $this->container->make(LogoutCurrentSession::class)->execute($this->name(), $account, $current);
    }

    public function logoutSession(Account $account, string $sessionId): void
    {
        $this->own($account);

        $this->container->make(LogoutSession::class)->execute($this->name(), $account, $sessionId);
    }

    public function logoutOthers(Account $account, CurrentToken $current): int
    {
        $this->own($account);

        return $this->container->make(LogoutOtherSessions::class)->execute($this->name(), $account, $current);
    }

    public function logoutEverywhere(Account $account): int
    {
        $this->own($account);

        return $this->container->make(LogoutEverywhere::class)->execute($this->name(), $account);
    }

    /**
     * Apply the guard's invalidation policy for a reason; returns the pair re-issued to
     * `$keep`'s device under `others` (null otherwise).
     */
    public function invalidate(Account $account, InvalidationReason $reason, ?CurrentToken $keep = null, ?SessionContext $context = null): ?TokenPair
    {
        $this->own($account);

        return $this->container->make(InvalidateAccountTokens::class)
            ->execute($this->config, $account, $reason, $keep, $context ?? new SessionContext)
            ->tokens;
    }

    // ── Account lifecycle ────────────────────────────────────────────────

    public function disable(Account $account, ?string $reason = null): void
    {
        $this->own($account);

        $this->container->make(DisableAccount::class)->execute($this->name(), $account, $reason);
    }

    public function enable(Account $account): void
    {
        $this->own($account);

        $this->container->make(EnableAccount::class)->execute($this->name(), $account);
    }

    public function unlock(Account $account): void
    {
        $this->own($account);

        $this->container->make(UnlockAccount::class)->execute($this->name(), $account);
    }

    /**
     * Every account-taking method refuses an account of another guard's model.
     */
    private function own(Account $account): void
    {
        $this->accounts()->ensureOwns($account);
    }
}
