<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\IdentifierStorage;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationDelivery;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\PasskeySecondFactor;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\RegistrationMode;
use RoundlyConsulting\Auth\Enums\RiskLevel;
use RoundlyConsulting\Auth\Enums\RiskReaction;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Enums\VerificationChannel;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('exposes the shipped defaults through typed accessors', function (): void {
    $guard = guardConfig();

    expect($guard->name())->toBe('users')
        ->and($guard->model())->toBe(User::class)
        ->and($guard->laravelGuard())->toBe('users')
        ->and($guard->identifierColumns())->toBe(['email'])
        ->and($guard->emailColumn())->toBe('email')
        ->and($guard->lowercasesIdentifiers())->toBeTrue()
        ->and($guard->caseInsensitiveLookup())->toBeFalse()
        ->and($guard->loginMethodEnabled(LoginMethod::Password))->toBeTrue()
        ->and($guard->loginMethodEnabled(LoginMethod::MagicLink))->toBeFalse()
        ->and($guard->loginMethodEnabled(LoginMethod::Invitation))->toBeTrue()
        ->and($guard->revealAccountState())->toBeTrue()
        ->and($guard->challengeTtl())->toBe(300)
        ->and($guard->challengeEnrolmentTtl())->toBe(900)
        ->and($guard->challengeMaxAttempts())->toBe(5)
        ->and($guard->allowsEnrolmentInChallenge())->toBeTrue()
        ->and($guard->enrolmentRequiresVerifiedEmail())->toBeTrue()
        ->and($guard->bindsChallengeToUserAgent())->toBeTrue()
        ->and($guard->bindsChallengeToIp())->toBeFalse()
        ->and($guard->bindsChallengeToDeviceHeader())->toBeTrue()
        ->and($guard->maxActiveChallenges())->toBe(3)
        ->and($guard->twoFactorMode())->toBe(TwoFactorMode::Optional)
        ->and($guard->twoFactorAfterEmailLogin())->toBeTrue()
        ->and($guard->twoFactorRequiredWithPasskey())->toBeFalse()
        ->and($guard->passkeySatisfiesRequiredTwoFactor())->toBeTrue()
        ->and($guard->twoFactorIssuer())->toBeNull()
        ->and($guard->rendersQrCode())->toBeTrue()
        ->and($guard->qrSize())->toBe(240)
        ->and($guard->passkeyMode())->toBe(PasskeyMode::Optional)
        ->and($guard->passkeySecondFactor())->toBe(PasskeySecondFactor::Allowed)
        ->and($guard->passkeySatisfiesMfa())->toBeTrue()
        ->and($guard->accessTtl())->toBeNull()
        ->and($guard->refreshTtl())->toBe(2_592_000)
        ->and($guard->refreshAbsoluteTtl())->toBe(7_776_000)
        ->and($guard->includesEmailClaim())->toBeTrue()
        ->and($guard->maxActiveSessions())->toBeNull()
        ->and($guard->registrationMode())->toBe(RegistrationMode::Closed)
        ->and($guard->registrationRequiresPassword())->toBeTrue()
        ->and($guard->loginAfterRegistration())->toBeTrue()
        ->and($guard->registrationRules())->toBeNull()
        ->and($guard->invitationsEnabled())->toBeFalse()
        ->and($guard->invitationTtl())->toBe(604_800)
        ->and($guard->invitationLocksEmail())->toBeTrue()
        ->and($guard->invitationReplacesPending())->toBeTrue()
        ->and($guard->invitationAllowsExistingEmail())->toBeFalse()
        ->and($guard->invitationResendCooldown())->toBe(60)
        ->and($guard->invitationMaxSends())->toBe(5)
        ->and($guard->invitationPreviewPayloadKeys())->toBe([])
        ->and($guard->invitationAbility())->toBe('authentication.invitations.manage')
        ->and($guard->verificationMode())->toBe(EmailVerificationMode::Optional)
        ->and($guard->verificationChannel())->toBe(VerificationChannel::Link)
        ->and($guard->verificationResendDecay())->toBe(60)
        ->and($guard->verifiesEmailOnEmailLogin())->toBeTrue()
        ->and($guard->emailChangeEnabled())->toBeTrue()
        ->and($guard->emailChangeNotifiesOldAddress())->toBeTrue()
        ->and($guard->emailChangeRequiresReauthentication())->toBeTrue()
        ->and($guard->magicLinkSameDevice())->toBeFalse()
        ->and($guard->passwordResetEnabled())->toBeTrue()
        ->and($guard->loginAfterPasswordReset())->toBeFalse()
        ->and($guard->passwordChangeEnabled())->toBeTrue()
        ->and($guard->rehashesPasswordsOnLogin())->toBeTrue()
        ->and($guard->passwordMinLength())->toBe(10)
        ->and($guard->passwordMaxLength())->toBe(128)
        ->and($guard->passwordRequiresLetters())->toBeFalse()
        ->and($guard->passwordRequiresMixedCase())->toBeFalse()
        ->and($guard->passwordRequiresNumbers())->toBeFalse()
        ->and($guard->passwordRequiresSymbols())->toBeFalse()
        ->and($guard->passwordMustNotContainIdentifier())->toBeTrue()
        ->and($guard->breachCheckEnabled())->toBeFalse()
        ->and($guard->breachThreshold())->toBe(0)
        ->and($guard->breachCheckTimeout())->toBe(3)
        ->and($guard->breachCheckFailsClosed())->toBeFalse()
        ->and($guard->lockoutEnabled())->toBeFalse()
        ->and($guard->lockoutThreshold())->toBe(10)
        ->and($guard->lockoutDuration())->toBe(900)
        ->and($guard->passwordResetUnlocks())->toBeTrue()
        ->and($guard->reauthenticationTimeout())->toBe(900)
        ->and($guard->reauthenticationMethods())->toBe(ReauthenticationMethod::cases())
        ->and($guard->reauthenticationRequiresSecondFactorWhenEnrolled())->toBeTrue()
        ->and($guard->freshLoginCountsAsReauthentication())->toBeTrue()
        ->and($guard->requiresReauthentication(SensitiveAction::DisableTwoFactor))->toBeTrue()
        ->and($guard->activityEnabled())->toBeTrue()
        ->and($guard->identifierStorage())->toBe(IdentifierStorage::Plain)
        ->and($guard->activityRetentionDays())->toBe(90)
        ->and($guard->newDeviceDetectionEnabled())->toBeTrue()
        ->and($guard->newDeviceHeader())->toBe('X-Device-Id')
        ->and($guard->newDeviceSkipsFirstLogin())->toBeTrue()
        ->and($guard->riskAssessor())->toBeNull()
        ->and($guard->riskReaction(RiskLevel::Low))->toBe(RiskReaction::Allow)
        ->and($guard->riskReaction(RiskLevel::Elevated))->toBe(RiskReaction::Notify)
        ->and($guard->riskReaction(RiskLevel::High))->toBe(RiskReaction::RequireSecondFactor)
        ->and($guard->riskDenialIsUniform())->toBeTrue()
        ->and($guard->localeHeader())->toBe('X-Locale')
        ->and($guard->supportedLocales())->toBe(['en'])
        ->and($guard->storesLocaleOnRegistration())->toBeTrue()
        ->and($guard->fillsLocaleOnLogin())->toBeTrue()
        ->and($guard->timezonesEnabled())->toBeTrue()
        ->and($guard->notificationDelivery())->toBe(NotificationDelivery::AfterResponse)
        ->and($guard->notificationConnection())->toBeNull()
        ->and($guard->notificationQueue())->toBeNull()
        ->and($guard->notificationClass(NotificationType::MagicLink))->toBe(MagicLinkNotification::class)
        ->and($guard->frontendUrl())->toBe('https://app.test')
        ->and($guard->routesEnabled())->toBeFalse()
        ->and($guard->routePrefix())->toBe('users/auth')
        ->and($guard->routeName())->toBe('authentication.users.')
        ->and($guard->routeMiddleware())->toBe(['api'])
        ->and($guard->authenticatedRouteMiddleware())->toBe([])
        ->and($guard->invitationManagementRoutes())->toBeFalse();
});

it('resolves every notification class, url template and throttle bucket', function (): void {
    $guard = guardConfig();

    foreach (NotificationType::cases() as $type) {
        expect($guard->notificationClass($type))->toBeString()->toStartWith('RoundlyConsulting\Auth\Notifications\\');
    }

    foreach (UrlKind::cases() as $kind) {
        expect($guard->urlTemplate($kind))->toContain('{token}')->toContain('#token=');
    }

    foreach (ThrottleKind::cases() as $kind) {
        expect($guard->throttle($kind)->maxAttempts)->toBeGreaterThan(0)
            ->and($guard->throttle($kind)->decaySeconds)->toBeGreaterThan(0);
    }

    expect($guard->throttle(ThrottleKind::Login)->maxAttempts)->toBe(5)
        ->and($guard->throttle(ThrottleKind::EmailRequestAccount)->decaySeconds)->toBe(3_600);
});

it('maps one-time token purposes to lifetimes, code lengths and attempt caps', function (): void {
    $guard = guardConfig(['verification' => ['channel' => 'code', 'code_length' => 8]]);

    expect($guard->ttl(OneTimeTokenPurpose::MagicLink))->toBe(900)
        ->and($guard->ttl(OneTimeTokenPurpose::EmailOtp))->toBe(600)
        ->and($guard->ttl(OneTimeTokenPurpose::Reauthentication))->toBe(600)
        ->and($guard->ttl(OneTimeTokenPurpose::EmailVerification))->toBe(86_400)
        ->and($guard->ttl(OneTimeTokenPurpose::PasswordReset))->toBe(3_600)
        ->and($guard->ttl(OneTimeTokenPurpose::EmailChange))->toBe(3_600)
        ->and($guard->usesCode(OneTimeTokenPurpose::EmailOtp))->toBeTrue()
        ->and($guard->usesCode(OneTimeTokenPurpose::EmailVerification))->toBeTrue()
        ->and($guard->usesCode(OneTimeTokenPurpose::MagicLink))->toBeFalse()
        ->and($guard->codeLength(OneTimeTokenPurpose::EmailVerification))->toBe(8)
        ->and($guard->codeLength(OneTimeTokenPurpose::EmailOtp))->toBe(6)
        ->and($guard->codeMaxAttempts(OneTimeTokenPurpose::EmailOtp))->toBe(5)
        ->and($guard->codeMaxAttempts(OneTimeTokenPurpose::EmailVerification))->toBe(5);
});

it('applies the invalidation matrix, never below all for disable and incidents', function (): void {
    $guard = guardConfig(['invalidation' => ['password_changed' => 'none']]);

    expect($guard->invalidationScope(InvalidationReason::PasswordChanged))->toBe(InvalidationScope::None)
        ->and($guard->invalidationScope(InvalidationReason::PasswordReset))->toBe(InvalidationScope::All)
        ->and($guard->invalidationScope(InvalidationReason::EmailChanged))->toBe(InvalidationScope::Others)
        ->and($guard->invalidationScope(InvalidationReason::TwoFactorChanged))->toBe(InvalidationScope::Others)
        ->and($guard->invalidationScope(InvalidationReason::PasskeyChanged))->toBe(InvalidationScope::None)
        ->and($guard->invalidationScope(InvalidationReason::AccountDisabled))->toBe(InvalidationScope::All)
        ->and($guard->invalidationScope(InvalidationReason::Logout))->toBe(InvalidationScope::All)
        ->and($guard->invalidationScope(InvalidationReason::Security))->toBe(InvalidationScope::All);
});

it('substitutes the guard into the route prefix and name and uses frontend_url', function (): void {
    $guard = guardConfig([
        'routes' => ['prefix' => '/api/{guard}/auth/', 'name' => 'api.{guard}.'],
        'notifications' => ['frontend_url' => 'https://clients.test/'],
        'locale' => ['supported' => ['sk', 'en']],
        'sessions' => ['max_active' => 3],
        'tokens' => ['access_ttl' => 600],
    ], 'clients');

    expect($guard->routePrefix())->toBe('api/clients/auth')
        ->and($guard->routeName())->toBe('api.clients.')
        ->and($guard->frontendUrl())->toBe('https://clients.test')
        ->and($guard->supportedLocales())->toBe(['sk', 'en'])
        ->and($guard->maxActiveSessions())->toBe(3)
        ->and($guard->accessTtl())->toBe(600);
});

it('refuses a blanked url template instead of the shipped one (strict config)', function (UrlKind $kind): void {
    expect(fn (): string => guardConfig(['notifications' => ['urls' => [$kind->value => '']]])->urlTemplate($kind))
        ->toThrow(AuthenticationMisconfigured::class, "authentication.guards.users.notifications.urls.{$kind->value}");
})->with(UrlKind::cases());

it('uses the shipped url template when one is unset (strict config)', function (UrlKind $kind): void {
    expect(guardConfig(['notifications' => ['urls' => [$kind->value => null]]])->urlTemplate($kind))
        ->toContain('{frontend}/auth/');
})->with(UrlKind::cases());

it('disables a notification configured as null', function (): void {
    expect(guardConfig(['notifications' => ['classes' => ['new_device' => null]]])->notificationClass(NotificationType::NewDevice))->toBeNull();
});

it('rejects an invalid enum value naming the exact key', function (): void {
    guardConfig(['two_factor' => ['mode' => 'sometimes']])->twoFactorMode();
})->throws(AuthenticationMisconfigured::class, 'authentication.guards.users.two_factor.mode');

it('rejects a model that is not an Account', function (): void {
    guardConfig(['model' => stdClass::class])->model();
})->throws(AuthenticationMisconfigured::class, 'authentication.guards.users.model');

it('resolves guards by name, morph class and model', function (): void {
    $registry = app(GuardRegistry::class);

    expect($registry->names())->toBe(['users', 'clients'])
        ->and($registry->has('clients'))->toBeTrue()
        ->and($registry->get()->name())->toBe('users')
        ->and($registry->forMorphClass((new User)->getMorphClass())?->name())->toBe('users')
        ->and($registry->forModel(new User)?->name())->toBe('users')
        ->and($registry->forMorphClass('nope'))->toBeNull();
});

it('throws for an unknown guard', function (): void {
    app(GuardRegistry::class)->get('staff');
})->throws(AuthenticationMisconfigured::class, 'staff');
