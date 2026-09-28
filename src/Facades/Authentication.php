<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Facades;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Auth\AuthenticationManager;
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
use RoundlyConsulting\Auth\Http\RouteRegistrar;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;

/**
 * `guard($name)` is one guard's API; every other per-guard method runs on the default
 * guard (`authentication.default`). No `Auth` alias on purpose — it would collide with
 * Laravel's own facade.
 *
 * @method static GuardContext guard(?string $name = null)
 * @method static list<string> guards()
 * @method static RouteRegistrar routes(string $guard)
 * @method static GuardContext|null currentGuard()
 * @method static bool routesRegistered(string $guard)
 * @method static PruneReport prune(?int $days = null)
 * @method static TwoFactorContext twoFactor()
 * @method static PasskeysContext passkeys()
 * @method static PasswordsContext passwords()
 * @method static EmailContext email()
 * @method static InvitationsContext invitations()
 * @method static ReauthenticationContext reauthentication()
 * @method static ChallengesContext challenges()
 * @method static string name()
 * @method static GuardConfig config()
 * @method static AccountRepository accounts()
 * @method static SessionContext contextFrom(Request $request)
 * @method static CurrentToken tokenFrom(Request $request)
 * @method static LoginResult attempt(PasswordCredentials $credentials, SessionContext $context)
 * @method static void requestMagicLink(string $email, SessionContext $context)
 * @method static LoginResult consumeMagicLink(string $token, SessionContext $context)
 * @method static void requestEmailOtp(string $email, SessionContext $context)
 * @method static LoginResult verifyEmailOtp(string $email, string $code, SessionContext $context)
 * @method static RequestOptionsData passkeyLoginOptions(SessionContext $context)
 * @method static LoginResult loginWithPasskey(AuthenticationResponseData $response, SessionContext $context)
 * @method static RegistrationResult register(RegistrationData $data)
 * @method static TokenPair issueTokens(Account $account, SessionContext $context, LoginMethod $method = LoginMethod::Host, list<AuthMethodReference> $authMethods = [])
 * @method static TokenPair refresh(string $refreshToken, SessionContext $context)
 * @method static Collection<int, SessionData> sessions(Account $account, ?string $currentSessionId = null)
 * @method static void logout(Account $account, CurrentToken $current)
 * @method static void logoutSession(Account $account, string $sessionId)
 * @method static int logoutOthers(Account $account, CurrentToken $current)
 * @method static int logoutEverywhere(Account $account)
 * @method static TokenPair|null invalidate(Account $account, InvalidationReason $reason, ?CurrentToken $keep = null, ?SessionContext $context = null)
 * @method static void disable(Account $account, ?string $reason = null)
 * @method static void enable(Account $account)
 * @method static CarbonImmutable lock(Account $account, ?int $seconds = null)
 * @method static void unlock(Account $account)
 * @method static Account updateLocale(Account $account, LocaleData $data)
 * @method static LengthAwarePaginator<int, LoginActivity> activity(Account $account, int $perPage = 20)
 *
 * @see AuthenticationManager
 * @see GuardContext
 */
final class Authentication extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return AuthenticationManager::class;
    }
}
