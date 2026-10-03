<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\IdentifierStorage;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;
use RoundlyConsulting\Auth\Enums\NotificationDelivery;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\PasskeySecondFactor;
use RoundlyConsulting\Auth\Enums\RegistrationMode;
use RoundlyConsulting\Auth\Enums\RiskLevel;
use RoundlyConsulting\Auth\Enums\RiskReaction;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Enums\VerificationChannel;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\ConfigValidation;
use RoundlyConsulting\Auth\Support\JwtAccessTokenRevoker;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\PackageToolkit\Exceptions\InvalidConfigurationException;

/*
 * Every non-boolean leaf is read strictly: not set (absent, null or blank — a host's `KEY=`)
 * takes the default, and a present value of the wrong shape throws naming the guard's key.
 * A junk TTL used to read as the default, a stray list entry was dropped.
 */

/**
 * Every integer leaf, with the accessor that reads it.
 *
 * @return array<string, array{0: array<string, mixed>, 1: string, 2: Closure(GuardConfig): mixed}>
 */
function strictIntegerLeaves(): array
{
    return [
        'challenge ttl' => [['challenge' => ['ttl' => 'five']], 'challenge.ttl', static fn (GuardConfig $g): int => $g->challengeTtl()],
        'challenge ttl zero' => [['challenge' => ['ttl' => 0]], 'challenge.ttl', static fn (GuardConfig $g): int => $g->challengeTtl()],
        'max attempts over the cap' => [['challenge' => ['max_attempts' => 1001]], 'challenge.max_attempts', static fn (GuardConfig $g): int => $g->challengeMaxAttempts()],
        'qr size float string' => [['two_factor' => ['qr' => ['size' => '240.5']]], 'two_factor.qr.size', static fn (GuardConfig $g): int => $g->qrSize()],
        'access ttl zero' => [['tokens' => ['access_ttl' => 0]], 'tokens.access_ttl', static fn (GuardConfig $g): ?int => $g->accessTtl()],
        'access ttl junk' => [['tokens' => ['access_ttl' => '15m']], 'tokens.access_ttl', static fn (GuardConfig $g): ?int => $g->accessTtl()],
        'refresh absolute negative' => [['tokens' => ['refresh_absolute_ttl' => -1]], 'tokens.refresh_absolute_ttl', static fn (GuardConfig $g): int => $g->refreshAbsoluteTtl()],
        'max sessions zero' => [['sessions' => ['max_active' => 0]], 'sessions.max_active', static fn (GuardConfig $g): ?int => $g->maxActiveSessions()],
        'resend cooldown junk' => [['invitations' => ['resend_cooldown' => 'a minute']], 'invitations.resend_cooldown', static fn (GuardConfig $g): int => $g->invitationResendCooldown()],
        'resend decay negative' => [['verification' => ['resend_decay' => '-1']], 'verification.resend_decay', static fn (GuardConfig $g): int => $g->verificationResendDecay()],
        'code length under 6' => [['email_otp' => ['length' => 4]], 'email_otp.length', static fn (GuardConfig $g): int => $g->codeLength(OneTimeTokenPurpose::EmailOtp)],
        'code length over 8' => [['verification' => ['code_length' => 9]], 'verification.code_length', static fn (GuardConfig $g): int => $g->codeLength(OneTimeTokenPurpose::EmailVerification)],
        'code attempts junk' => [['email_otp' => ['max_attempts' => 'five']], 'email_otp.max_attempts', static fn (GuardConfig $g): int => $g->codeMaxAttempts(OneTimeTokenPurpose::EmailOtp)],
        'password max under min' => [['passwords' => ['policy' => ['min' => 12, 'max' => 8]]], 'passwords.policy.max', static fn (GuardConfig $g): int => $g->passwordMaxLength()],
        'breach threshold junk' => [['passwords' => ['policy' => ['uncompromised' => ['threshold' => 'any']]]], 'passwords.policy.uncompromised.threshold', static fn (GuardConfig $g): int => $g->breachThreshold()],
        'magic link ttl junk' => [['magic_link' => ['ttl' => '1e3']], 'magic_link.ttl', static fn (GuardConfig $g): int => $g->ttl(OneTimeTokenPurpose::MagicLink)],
        'throttle max junk' => [['throttle' => ['login' => ['max' => 'many']]], 'throttle.login.max', static fn (GuardConfig $g): mixed => $g->throttle(ThrottleKind::Login)],
        'throttle decay zero' => [['throttle' => ['refresh' => ['decay' => 0]]], 'throttle.refresh.decay', static fn (GuardConfig $g): mixed => $g->throttle(ThrottleKind::Refresh)],
        'lockout threshold junk' => [['lockout' => ['threshold' => true]], 'lockout.threshold', static fn (GuardConfig $g): int => $g->lockoutThreshold()],
        'retention days junk' => [['activity' => ['retention_days' => 'a week']], 'activity.retention_days', static fn (GuardConfig $g): int => $g->activityRetentionDays()],
    ];
}

it('refuses a junk or out-of-range integer leaf instead of the default (strict config)', function (array $overrides, string $key, Closure $read): void {
    expect(fn (): mixed => $read(guardConfig($overrides)))
        ->toThrow(AuthenticationMisconfigured::class, "authentication.guards.users.{$key}");
})->with(strictIntegerLeaves());

it('reads canonical integer strings and keeps 0 where it has a meaning (strict config)', function (): void {
    $guard = guardConfig([
        'challenge' => ['ttl' => '600'],
        'tokens' => ['access_ttl' => ' 120 ', 'refresh_absolute_ttl' => '0'],
        'sessions' => ['max_active' => '2'],
        'invitations' => ['resend_cooldown' => 0],
        'email_otp' => ['length' => '8'],
        'throttle' => ['login' => ['max' => '3', 'decay' => '30']],
    ]);

    expect($guard->challengeTtl())->toBe(600)
        ->and($guard->accessTtl())->toBe(120)
        ->and($guard->refreshAbsoluteTtl())->toBe(0)
        ->and($guard->maxActiveSessions())->toBe(2)
        ->and($guard->invitationResendCooldown())->toBe(0)
        ->and($guard->codeLength(OneTimeTokenPurpose::EmailOtp))->toBe(8)
        ->and($guard->throttle(ThrottleKind::Login)->maxAttempts)->toBe(3)
        ->and($guard->throttle(ThrottleKind::Login)->decaySeconds)->toBe(30);
});

it('reads unset nullable integers as null (strict config)', function (mixed $unset): void {
    $guard = guardConfig(['tokens' => ['access_ttl' => $unset], 'sessions' => ['max_active' => $unset]]);

    expect($guard->accessTtl())->toBeNull()
        ->and($guard->maxActiveSessions())->toBeNull();
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('reads a blank integer leaf as not set, so the default applies (strict config)', function (): void {
    $guard = guardConfig([
        'challenge' => ['ttl' => '', 'max_attempts' => ' '],
        'activity' => ['retention_days' => ''],
        'throttle' => ['login' => ['max' => '', 'decay' => '']],
    ]);
    $shipped = guardConfig();

    expect($guard->challengeTtl())->toBe(300)
        ->and($guard->challengeMaxAttempts())->toBe(5)
        ->and($guard->activityRetentionDays())->toBe($shipped->activityRetentionDays())
        ->and($guard->throttle(ThrottleKind::Login)->maxAttempts)->toBe($shipped->throttle(ThrottleKind::Login)->maxAttempts)
        ->and($guard->throttle(ThrottleKind::Login)->decaySeconds)->toBe($shipped->throttle(ThrottleKind::Login)->decaySeconds);
});

it('reads a blank string leaf as not set, so the shipped one applies (strict config)', function (): void {
    $guard = guardConfig([
        'identifier' => ['email_column' => '', 'normalize' => ''],
        'invitations' => ['ability' => ' '],
        'activity' => ['new_device' => ['header' => ' ']],
        'routes' => ['prefix' => '', 'name' => '', 'middleware' => ''],
        'risk' => ['deny_response' => ''],
    ]);

    expect($guard->emailColumn())->toBe('email')
        ->and($guard->lowercasesIdentifiers())->toBeTrue()
        ->and($guard->invitationAbility())->toBe('authentication.invitations.manage')
        ->and($guard->newDeviceHeader())->toBe('X-Device-Id')
        ->and($guard->routePrefix())->toBe('users/auth')
        ->and($guard->routeName())->toBe('authentication.users.')
        ->and($guard->routeMiddleware())->toBe([])
        ->and($guard->riskDenialIsUniform())->toBeTrue();
});

it('reads a blank enum leaf as not set, so the shipped mode applies (strict config)', function (): void {
    $guard = guardConfig([
        'two_factor' => ['mode' => ''],
        'passkeys' => ['mode' => ' ', 'second_factor' => ''],
        'registration' => ['mode' => ''],
        'verification' => ['mode' => '', 'channel' => ''],
        'activity' => ['store_identifier' => ''],
        'notifications' => ['delivery' => ''],
        'risk' => ['reactions' => ['elevated' => '', 'high' => '']],
        'invalidation' => ['password_changed' => '', 'password_reset' => '', 'passkey_changed' => ''],
    ]);

    expect($guard->twoFactorMode())->toBe(TwoFactorMode::Optional)
        ->and($guard->passkeyMode())->toBe(PasskeyMode::Optional)
        ->and($guard->passkeySecondFactor())->toBe(PasskeySecondFactor::Allowed)
        ->and($guard->registrationMode())->toBe(RegistrationMode::Closed)
        ->and($guard->verificationMode())->toBe(EmailVerificationMode::Optional)
        ->and($guard->verificationChannel())->toBe(VerificationChannel::Link)
        ->and($guard->identifierStorage())->toBe(IdentifierStorage::Plain)
        ->and($guard->notificationDelivery())->toBe(NotificationDelivery::AfterResponse)
        ->and($guard->riskReaction(RiskLevel::Elevated))->toBe(RiskReaction::Notify)
        ->and($guard->riskReaction(RiskLevel::High))->toBe(RiskReaction::RequireSecondFactor)
        ->and($guard->invalidationScope(InvalidationReason::PasswordChanged))->toBe(InvalidationScope::Others)
        ->and($guard->invalidationScope(InvalidationReason::PasswordReset))->toBe(InvalidationScope::All)
        ->and($guard->invalidationScope(InvalidationReason::PasskeyChanged))->toBe(InvalidationScope::None);
});

it('still refuses a junk enum or switch spelling (strict config)', function (array $overrides, string $key, Closure $read): void {
    expect(fn (): mixed => $read(guardConfig($overrides)))
        ->toThrow(AuthenticationMisconfigured::class, "authentication.guards.users.{$key}");
})->with([
    'two-factor mode typo' => [['two_factor' => ['mode' => 'Optional']], 'two_factor.mode', static fn (GuardConfig $g): TwoFactorMode => $g->twoFactorMode()],
    'risk reaction typo' => [['risk' => ['reactions' => ['high' => 'block']]], 'risk.reactions.high', static fn (GuardConfig $g): RiskReaction => $g->riskReaction(RiskLevel::High)],
    'normalize typo' => [['identifier' => ['normalize' => 'lower']], 'identifier.normalize', static fn (GuardConfig $g): bool => $g->lowercasesIdentifiers()],
]);

it('refuses a mistyped string leaf instead of the shipped one (strict config)', function (array $overrides, string $key, Closure $read): void {
    expect(fn (): mixed => $read(guardConfig($overrides)))
        ->toThrow(AuthenticationMisconfigured::class, "authentication.guards.users.{$key}");
})->with([
    'email column not a string' => [['identifier' => ['email_column' => ['email']]], 'identifier.email_column', static fn (GuardConfig $g): string => $g->emailColumn()],
    'invitation ability not a string' => [['invitations' => ['ability' => ['manage']]], 'invitations.ability', static fn (GuardConfig $g): string => $g->invitationAbility()],
    'device header not a string' => [['activity' => ['new_device' => ['header' => 7]]], 'activity.new_device.header', static fn (GuardConfig $g): string => $g->newDeviceHeader()],
    'route prefix not a string' => [['routes' => ['prefix' => false]], 'routes.prefix', static fn (GuardConfig $g): string => $g->routePrefix()],
    'route name not a string' => [['routes' => ['name' => 5]], 'routes.name', static fn (GuardConfig $g): string => $g->routeName()],
    'laravel guard not a string' => [['laravel_guard' => ['users']], 'laravel_guard', static fn (GuardConfig $g): string => $g->laravelGuard()],
    'issuer not a string' => [['two_factor' => ['issuer' => 42]], 'two_factor.issuer', static fn (GuardConfig $g): ?string => $g->twoFactorIssuer()],
    'queue not a string' => [['notifications' => ['queue' => false]], 'notifications.queue', static fn (GuardConfig $g): ?string => $g->notificationQueue()],
    'notification class not a string' => [['notifications' => ['classes' => ['new_device' => false]]], 'notifications.classes.new_device', static fn (GuardConfig $g): ?string => $g->notificationClass(NotificationType::NewDevice)],
    'frontend url not a string' => [['notifications' => ['frontend_url' => ['https://app']]], 'notifications.frontend_url', static fn (GuardConfig $g): string => $g->frontendUrl()],
]);

it('reads a blank optional string as unset (strict config)', function (): void {
    $guard = guardConfig(['two_factor' => ['issuer' => ''], 'notifications' => ['queue' => '  ', 'frontend_url' => '']]);

    expect($guard->twoFactorIssuer())->toBeNull()
        ->and($guard->notificationQueue())->toBeNull()
        ->and($guard->frontendUrl())->toBe($guard->appUrl());
});

it('refuses a mistyped list leaf instead of dropping entries (strict config)', function (array $overrides, string $key, Closure $read): void {
    expect(fn (): mixed => $read(guardConfig($overrides)))
        ->toThrow(AuthenticationMisconfigured::class, "authentication.guards.users.{$key}");
})->with([
    'columns not a list' => [['identifier' => ['columns' => 'email']], 'identifier.columns', static fn (GuardConfig $g): array => $g->identifierColumns()],
    'middleware with a non-string' => [['routes' => ['middleware' => ['api', 42]]], 'routes.middleware', static fn (GuardConfig $g): array => $g->routeMiddleware()],
    'authenticated middleware with a blank' => [['routes' => ['authenticated_middleware' => ['verified', '']]], 'routes.authenticated_middleware', static fn (GuardConfig $g): array => $g->authenticatedRouteMiddleware()],
    'locales a map' => [['locale' => ['supported' => ['en' => 'English']]], 'locale.supported', static fn (GuardConfig $g): array => $g->supportedLocales()],
    'reauthentication methods not a list' => [['reauthentication' => ['methods' => 'password']], 'reauthentication.methods', static fn (GuardConfig $g): array => $g->reauthenticationMethods()],
]);

it('refuses a guard whose scalar leaf is junk when it resolves, before any flow runs (strict config)', function (): void {
    $this->configureGuard('users', ['challenge.ttl' => 'five']);

    $registry = app(GuardRegistry::class);

    expect(implode("\n", ConfigValidation::problems($registry->all()['users'], $registry)))->toContain('authentication.guards.users.challenge.ttl')
        ->and(fn () => $registry->get('users'))->toThrow(AuthenticationMisconfigured::class, 'challenge.ttl');
});

it('refuses a non-string table or column name (strict config)', function (string $key, mixed $junk, Closure $read): void {
    config()->set($key, $junk);

    expect($read)->toThrow(AuthenticationMisconfigured::class, $key);
})->with([
    'challenges table not a string' => ['authentication.tables.challenges', false, static fn (): string => Tables::challenges()],
    'activities table not a string' => ['authentication.tables.login_activities', ['x'], static fn (): string => Tables::loginActivities()],
    'token version column not a string' => ['authentication.columns.token_version', ['token_version'], static fn (): string => Columns::tokenVersion()],
    'locked until column not a string' => ['authentication.columns.locked_until', 1, static fn (): string => Columns::lockedUntil()],
]);

it('reads absent or blank table and column names as the shipped ones (strict config)', function (mixed $unset): void {
    config()->set('authentication.tables.challenges', $unset);
    config()->set('authentication.columns.token_version', $unset);

    expect(Tables::challenges())->toBe('auth_login_challenges')
        ->and(Columns::tokenVersion())->toBe('token_version');
})->with(['null' => [null], 'blank' => [''], 'whitespace' => [' ']]);

it('refuses a non-string hash key instead of deriving one (strict config)', function (): void {
    config()->set('authentication.hash_key', ['secret']);

    expect(fn (): bool => app(SecretHasher::class)->usesDerivedKey())
        ->toThrow(AuthenticationMisconfigured::class, 'authentication.hash_key');
});

it('derives the hash key from APP_KEY when it is blank (strict config)', function (): void {
    config()->set('authentication.hash_key', '  ');

    expect(app(SecretHasher::class)->usesDerivedKey())->toBeTrue();
});

it('refuses a non-string reauthentication store (strict config)', function (): void {
    config()->set('authentication.reauthentication_store', ['redis']);

    expect(fn () => app(ReauthenticationMarker::class)->pullCeremony('users', 'session'))
        ->toThrow(AuthenticationMisconfigured::class, 'authentication.reauthentication_store');
});

it('refuses mistyped guard sections instead of reading them as empty (strict config)', function (string $key, mixed $junk, string $named): void {
    config()->set($key, $junk);

    expect(fn (): array => (new GuardRegistry)->all())->toThrow(AuthenticationMisconfigured::class, $named);
})->with([
    'defaults not an array' => ['authentication.defaults', 'none', 'authentication.defaults'],
    'guards not an array' => ['authentication.guards', 'users', 'authentication.guards'],
    'a guard keyed by position' => ['authentication.guards', [['model' => 'App\\Models\\User']], 'keyed by guard name'],
    'a guard not an array' => ['authentication.guards', ['users' => 'App\\Models\\User'], 'authentication.guards.users'],
]);

it('refuses a non-string default guard (strict config)', function (): void {
    config()->set('authentication.default', ['users']);

    expect(fn (): string => (new GuardRegistry)->defaultGuard())->toThrow(AuthenticationMisconfigured::class, 'authentication.default');
});

it('reads a blank default guard as not set, so users applies (strict config)', function (mixed $unset): void {
    config()->set('authentication.default', $unset);

    expect((new GuardRegistry)->defaultGuard())->toBe('users');
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('reads the jwt ttl and leeway strictly when sizing the denylist horizon (strict config)', function (string $key): void {
    // Resolve the denylist first, so it is this package's own read of the key that throws.
    Jwt::denylist();
    config()->set($key, 'five');

    expect(fn () => (new JwtAccessTokenRevoker)->revoke('jti-1'))
        ->toThrow(InvalidConfigurationException::class, $key);
})->with(['jwt.ttl', 'jwt.leeway']);
