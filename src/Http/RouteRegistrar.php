<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http;

use Illuminate\Routing\Router;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\RegistrationMode;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Http\Controllers\Account\LoginActivityController;
use RoundlyConsulting\Auth\Http\Controllers\Account\MeController;
use RoundlyConsulting\Auth\Http\Controllers\Account\ReauthenticateController;
use RoundlyConsulting\Auth\Http\Controllers\Account\ReauthenticationPasskeyOptionsController;
use RoundlyConsulting\Auth\Http\Controllers\Account\SendReauthenticationCodeController;
use RoundlyConsulting\Auth\Http\Controllers\Account\UpdateLocaleController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\ConfirmTwoFactorEnrolmentController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\PasskeyController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\PasskeyEnrolmentController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\PasskeyEnrolmentOptionsController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\PasskeyOptionsController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\StartTwoFactorEnrolmentController;
use RoundlyConsulting\Auth\Http\Controllers\Challenge\TwoFactorController;
use RoundlyConsulting\Auth\Http\Controllers\Email\ConfirmEmailChangeController;
use RoundlyConsulting\Auth\Http\Controllers\Email\RequestEmailChangeController;
use RoundlyConsulting\Auth\Http\Controllers\Email\ResendVerificationController;
use RoundlyConsulting\Auth\Http\Controllers\Email\SendVerificationController;
use RoundlyConsulting\Auth\Http\Controllers\Email\VerifyEmailController;
use RoundlyConsulting\Auth\Http\Controllers\Invitations\AcceptInvitationController;
use RoundlyConsulting\Auth\Http\Controllers\Invitations\CreateInvitationController;
use RoundlyConsulting\Auth\Http\Controllers\Invitations\ListInvitationsController;
use RoundlyConsulting\Auth\Http\Controllers\Invitations\PreviewInvitationController;
use RoundlyConsulting\Auth\Http\Controllers\Invitations\ResendInvitationController;
use RoundlyConsulting\Auth\Http\Controllers\Invitations\RevokeInvitationController;
use RoundlyConsulting\Auth\Http\Controllers\Login\ConsumeMagicLinkController;
use RoundlyConsulting\Auth\Http\Controllers\Login\PasskeyLoginController;
use RoundlyConsulting\Auth\Http\Controllers\Login\PasskeyLoginOptionsController;
use RoundlyConsulting\Auth\Http\Controllers\Login\PasswordLoginController;
use RoundlyConsulting\Auth\Http\Controllers\Login\RequestEmailOtpController;
use RoundlyConsulting\Auth\Http\Controllers\Login\RequestMagicLinkController;
use RoundlyConsulting\Auth\Http\Controllers\Login\VerifyEmailOtpController;
use RoundlyConsulting\Auth\Http\Controllers\Passkeys\ListPasskeysController;
use RoundlyConsulting\Auth\Http\Controllers\Passkeys\RegisterPasskeyController;
use RoundlyConsulting\Auth\Http\Controllers\Passkeys\RegistrationOptionsController;
use RoundlyConsulting\Auth\Http\Controllers\Passkeys\RemovePasskeyController;
use RoundlyConsulting\Auth\Http\Controllers\Passkeys\RenamePasskeyController;
use RoundlyConsulting\Auth\Http\Controllers\Passwords\ChangePasswordController;
use RoundlyConsulting\Auth\Http\Controllers\Passwords\ForgotPasswordController;
use RoundlyConsulting\Auth\Http\Controllers\Passwords\ResetPasswordController;
use RoundlyConsulting\Auth\Http\Controllers\Registration\RegisterController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\ListSessionsController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\LogoutController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\LogoutEverywhereController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\LogoutOthersController;
use RoundlyConsulting\Auth\Http\Controllers\Sessions\RevokeSessionController;
use RoundlyConsulting\Auth\Http\Controllers\Tokens\RefreshController;
use RoundlyConsulting\Auth\Http\Controllers\TwoFactor\ConfirmController;
use RoundlyConsulting\Auth\Http\Controllers\TwoFactor\DisableController;
use RoundlyConsulting\Auth\Http\Controllers\TwoFactor\EnableController;
use RoundlyConsulting\Auth\Http\Controllers\TwoFactor\RegenerateRecoveryCodesController;
use RoundlyConsulting\Auth\Http\Controllers\TwoFactor\StatusController;

/**
 * Registers a guard's opt-in JSON endpoints (`Authentication::routes('users')`, or
 * `routes.enabled = true`). Fluent; registers itself on destruct when `register()` was
 * not called, like Laravel's pending resource registration.
 *
 * Every route carries `authentication.guard:{guard}` and `authentication.no-store`,
 * and is registered only when its feature is enabled for the guard. Tokens always
 * travel in request bodies, never in the path or query string.
 */
final class RouteRegistrar
{
    private string $prefix;

    private string $name;

    /** @var list<string> */
    private array $middleware;

    /** @var list<string> */
    private array $authenticatedMiddleware;

    /** @var list<string> */
    private array $only = [];

    /** @var list<string> */
    private array $except = [];

    private bool $registered = false;

    public function __construct(
        private readonly Router $router,
        private readonly GuardConfig $guard,
        private readonly AuthenticationManager $manager,
    ) {
        $this->prefix = $guard->routePrefix();
        $this->name = $guard->routeName();
        $this->middleware = $guard->routeMiddleware();
        $this->authenticatedMiddleware = $guard->authenticatedRouteMiddleware();
    }

    public function __destruct()
    {
        if (! $this->registered) {
            $this->register();
        }
    }

    public function prefix(string $prefix): self
    {
        $this->prefix = trim($prefix, '/');

        return $this;
    }

    public function name(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * @param  list<string>|string  $middleware
     */
    public function middleware(array|string $middleware): self
    {
        $this->middleware = is_array($middleware) ? $middleware : [$middleware];

        return $this;
    }

    /**
     * @param  list<string>|string  $middleware
     */
    public function authenticatedMiddleware(array|string $middleware): self
    {
        $this->authenticatedMiddleware = is_array($middleware) ? $middleware : [$middleware];

        return $this;
    }

    /**
     * @param  list<string>  $groups
     */
    public function only(array $groups): self
    {
        $this->only = $groups;

        return $this;
    }

    /**
     * @param  list<string>  $groups
     */
    public function except(array $groups): self
    {
        $this->except = $groups;

        return $this;
    }

    public function register(): void
    {
        if ($this->registered) {
            return;
        }

        $this->registered = true;
        $this->manager->markRoutesRegistered($this->guard->name(), $this->prefix, $this->name);

        $guard = $this->guard->name();

        $this->router->group([
            'prefix' => $this->prefix,
            'as' => $this->name,
            'middleware' => [...$this->middleware, 'authentication.guard:'.$guard, 'authentication.no-store'],
        ], function (Router $router) use ($guard): void {
            foreach ($this->definitions() as $definition) {
                $middleware = $definition->authenticated
                    ? ['auth:'.$this->guard->laravelGuard(), ...$this->authenticatedMiddleware, ...$definition->middleware]
                    : $definition->middleware;

                $router->addRoute($definition->method, $definition->uri, $definition->controller)
                    ->name($definition->name)
                    ->middleware($middleware)
                    ->defaults(RequestGuard::ATTRIBUTE, $guard);
            }
        });
    }

    /**
     * The enabled endpoints this registrar will register (after only/except).
     *
     * @return list<RouteDefinition>
     */
    public function definitions(): array
    {
        return array_values(array_filter(
            $this->all(),
            fn (RouteDefinition $route): bool => $route->enabled
                && ($this->only === [] || in_array($route->group, $this->only, true))
                && ! in_array($route->group, $this->except, true),
        ));
    }

    /**
     * @return list<RouteDefinition>
     */
    private function all(): array
    {
        $twoFactor = $this->guard->twoFactorMode() !== TwoFactorMode::Off;
        $passkeys = $this->guard->passkeyMode() !== PasskeyMode::Off;
        $enrolment = $this->guard->allowsEnrolmentInChallenge();
        $invitations = $this->guard->invitationsEnabled();
        $manage = $invitations && $this->guard->invitationManagementRoutes();
        $can = ['can:'.$this->guard->invitationAbility()];
        $verification = $this->guard->verificationMode() !== EmailVerificationMode::Off;

        return [
            // Login
            new RouteDefinition('login', 'POST', 'login', 'login', PasswordLoginController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::Password)),
            new RouteDefinition('login', 'POST', 'login/magic-link', 'login.magic-link', RequestMagicLinkController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::MagicLink)),
            new RouteDefinition('login', 'POST', 'login/magic-link/consume', 'login.magic-link.consume', ConsumeMagicLinkController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::MagicLink)),
            new RouteDefinition('login', 'POST', 'login/otp', 'login.otp', RequestEmailOtpController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::EmailOtp)),
            new RouteDefinition('login', 'POST', 'login/otp/verify', 'login.otp.verify', VerifyEmailOtpController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::EmailOtp)),
            new RouteDefinition('login', 'POST', 'login/passkey/options', 'login.passkey.options', PasskeyLoginOptionsController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::Passkey)),
            new RouteDefinition('login', 'POST', 'login/passkey', 'login.passkey', PasskeyLoginController::class, enabled: $this->guard->loginMethodEnabled(LoginMethod::Passkey)),

            // Challenge
            new RouteDefinition('challenge', 'POST', 'challenge/two-factor', 'challenge.two-factor', TwoFactorController::class, enabled: $twoFactor),
            new RouteDefinition('challenge', 'POST', 'challenge/two-factor/enrol', 'challenge.two-factor.enrol', StartTwoFactorEnrolmentController::class, enabled: $twoFactor && $enrolment),
            new RouteDefinition('challenge', 'POST', 'challenge/two-factor/enrol/confirm', 'challenge.two-factor.enrol.confirm', ConfirmTwoFactorEnrolmentController::class, enabled: $twoFactor && $enrolment),
            new RouteDefinition('challenge', 'POST', 'challenge/passkey/options', 'challenge.passkey.options', PasskeyOptionsController::class, enabled: $passkeys),
            new RouteDefinition('challenge', 'POST', 'challenge/passkey', 'challenge.passkey', PasskeyController::class, enabled: $passkeys),
            new RouteDefinition('challenge', 'POST', 'challenge/passkey/enrol/options', 'challenge.passkey.enrol.options', PasskeyEnrolmentOptionsController::class, enabled: $passkeys && $enrolment),
            new RouteDefinition('challenge', 'POST', 'challenge/passkey/enrol', 'challenge.passkey.enrol', PasskeyEnrolmentController::class, enabled: $passkeys && $enrolment),

            // Tokens
            new RouteDefinition('tokens', 'POST', 'refresh', 'refresh', RefreshController::class),

            // Registration & invitations
            new RouteDefinition('registration', 'POST', 'register', 'register', RegisterController::class, enabled: $this->guard->registrationMode() !== RegistrationMode::Closed),
            new RouteDefinition('invitations', 'POST', 'invitations/preview', 'invitations.preview', PreviewInvitationController::class, enabled: $invitations),
            new RouteDefinition('invitations', 'POST', 'invitations/accept', 'invitations.accept', AcceptInvitationController::class, enabled: $invitations),

            // Passwords
            new RouteDefinition('passwords', 'POST', 'password/forgot', 'password.forgot', ForgotPasswordController::class, enabled: $this->guard->passwordResetEnabled()),
            new RouteDefinition('passwords', 'POST', 'password/reset', 'password.reset', ResetPasswordController::class, enabled: $this->guard->passwordResetEnabled()),
            new RouteDefinition('passwords', 'PUT', 'password', 'password.update', ChangePasswordController::class, authenticated: true, enabled: $this->guard->passwordChangeEnabled()),

            // Email
            new RouteDefinition('email', 'POST', 'email/verify', 'email.verify', VerifyEmailController::class, enabled: $verification),
            new RouteDefinition('email', 'POST', 'email/verification/resend', 'email.resend', ResendVerificationController::class, enabled: $verification),
            new RouteDefinition('email', 'POST', 'email/verification', 'email.send', SendVerificationController::class, authenticated: true, enabled: $verification),
            new RouteDefinition('email', 'POST', 'email/change', 'email.change', RequestEmailChangeController::class, authenticated: true, enabled: $this->guard->emailChangeEnabled()),
            new RouteDefinition('email', 'POST', 'email/change/confirm', 'email.change.confirm', ConfirmEmailChangeController::class, enabled: $this->guard->emailChangeEnabled()),

            // Account
            new RouteDefinition('account', 'GET', 'me', 'me', MeController::class, authenticated: true),
            new RouteDefinition('account', 'PATCH', 'locale', 'locale', UpdateLocaleController::class, authenticated: true),
            new RouteDefinition('account', 'POST', 'reauthenticate', 'reauthenticate', ReauthenticateController::class, authenticated: true),
            new RouteDefinition('account', 'POST', 'reauthenticate/passkey/options', 'reauthenticate.passkey.options', ReauthenticationPasskeyOptionsController::class, authenticated: true, enabled: $passkeys),
            new RouteDefinition('account', 'POST', 'reauthenticate/otp', 'reauthenticate.otp', SendReauthenticationCodeController::class, authenticated: true, enabled: in_array(ReauthenticationMethod::EmailOtp, $this->guard->reauthenticationMethods(), true)),
            new RouteDefinition('account', 'GET', 'activity', 'activity', LoginActivityController::class, authenticated: true, enabled: $this->guard->activityEnabled()),

            // Sessions
            new RouteDefinition('sessions', 'POST', 'logout', 'logout', LogoutController::class, authenticated: true),
            new RouteDefinition('sessions', 'POST', 'logout/others', 'logout.others', LogoutOthersController::class, authenticated: true),
            new RouteDefinition('sessions', 'POST', 'logout/everywhere', 'logout.everywhere', LogoutEverywhereController::class, authenticated: true),
            new RouteDefinition('sessions', 'GET', 'sessions', 'sessions', ListSessionsController::class, authenticated: true),
            new RouteDefinition('sessions', 'DELETE', 'sessions/{session}', 'sessions.destroy', RevokeSessionController::class, authenticated: true),

            // Two-factor management
            new RouteDefinition('two-factor', 'GET', 'two-factor', 'two-factor.show', StatusController::class, authenticated: true, enabled: $twoFactor),
            new RouteDefinition('two-factor', 'POST', 'two-factor', 'two-factor.enable', EnableController::class, authenticated: true, enabled: $twoFactor),
            new RouteDefinition('two-factor', 'POST', 'two-factor/confirm', 'two-factor.confirm', ConfirmController::class, authenticated: true, enabled: $twoFactor),
            new RouteDefinition('two-factor', 'DELETE', 'two-factor', 'two-factor.disable', DisableController::class, authenticated: true, enabled: $this->guard->twoFactorMode() === TwoFactorMode::Optional),
            new RouteDefinition('two-factor', 'POST', 'two-factor/recovery-codes', 'two-factor.recovery-codes', RegenerateRecoveryCodesController::class, authenticated: true, enabled: $twoFactor),

            // Invitation management (admin)
            new RouteDefinition('invitations.manage', 'GET', 'invitations', 'invitations.index', ListInvitationsController::class, authenticated: true, enabled: $manage, middleware: $can),
            new RouteDefinition('invitations.manage', 'POST', 'invitations', 'invitations.store', CreateInvitationController::class, authenticated: true, enabled: $manage, middleware: $can),
            new RouteDefinition('invitations.manage', 'POST', 'invitations/{invitation}/resend', 'invitations.resend', ResendInvitationController::class, authenticated: true, enabled: $manage, middleware: $can),
            new RouteDefinition('invitations.manage', 'DELETE', 'invitations/{invitation}', 'invitations.destroy', RevokeInvitationController::class, authenticated: true, enabled: $manage, middleware: $can),

            // Passkey management
            new RouteDefinition('passkeys', 'GET', 'passkeys', 'passkeys.index', ListPasskeysController::class, authenticated: true, enabled: $passkeys),
            new RouteDefinition('passkeys', 'POST', 'passkeys/options', 'passkeys.options', RegistrationOptionsController::class, authenticated: true, enabled: $passkeys),
            new RouteDefinition('passkeys', 'POST', 'passkeys', 'passkeys.store', RegisterPasskeyController::class, authenticated: true, enabled: $passkeys),
            new RouteDefinition('passkeys', 'PATCH', 'passkeys/{passkey}', 'passkeys.update', RenamePasskeyController::class, authenticated: true, enabled: $passkeys),
            new RouteDefinition('passkeys', 'DELETE', 'passkeys/{passkey}', 'passkeys.destroy', RemovePasskeyController::class, authenticated: true, enabled: $passkeys),
        ];
    }
}
