<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AboutSection;
use RoundlyConsulting\Auth\Support\ConfigValidation;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Regression (env-boolean sweep): every guard switch was read with `(bool)`, and the
 * env-backed ones (`login.*`, `passwords.policy.uncompromised.enabled`) were cast
 * `(bool) env(...)` in the config file. env() only converts "true"/"false", so
 * `AUTHENTICATION_LOGIN_PASSWORD=off` was cast to TRUE — password login stayed open — and
 * `AUTHENTICATION_PASSWORD_BREACH_CHECK=no` kept the breach check on. Every switch (and the
 * `about` rows built from them) now reads the value as a boolean.
 */
dataset('boolean guard settings', [
    'caseInsensitiveLookup' => ['caseInsensitiveLookup', ['identifier', 'case_insensitive_lookup']],
    'revealAccountState' => ['revealAccountState', ['login', 'reveal_account_state']],
    'allowsEnrolmentInChallenge' => ['allowsEnrolmentInChallenge', ['challenge', 'allow_enrolment']],
    'enrolmentRequiresVerifiedEmail' => ['enrolmentRequiresVerifiedEmail', ['challenge', 'enrolment_requires_verified_email']],
    'bindsChallengeToUserAgent' => ['bindsChallengeToUserAgent', ['challenge', 'bind', 'user_agent']],
    'bindsChallengeToIp' => ['bindsChallengeToIp', ['challenge', 'bind', 'ip']],
    'bindsChallengeToDeviceHeader' => ['bindsChallengeToDeviceHeader', ['challenge', 'bind', 'device_header']],
    'twoFactorAfterEmailLogin' => ['twoFactorAfterEmailLogin', ['two_factor', 'after_email_login']],
    'twoFactorRequiredWithPasskey' => ['twoFactorRequiredWithPasskey', ['two_factor', 'required_with_passkey']],
    'passkeySatisfiesRequiredTwoFactor' => ['passkeySatisfiesRequiredTwoFactor', ['two_factor', 'passkey_satisfies_required']],
    'rendersQrCode' => ['rendersQrCode', ['two_factor', 'qr', 'enabled']],
    'passkeySatisfiesMfa' => ['passkeySatisfiesMfa', ['passkeys', 'satisfies_mfa']],
    'includesEmailClaim' => ['includesEmailClaim', ['tokens', 'include_email']],
    'registrationRequiresPassword' => ['registrationRequiresPassword', ['registration', 'require_password']],
    'loginAfterRegistration' => ['loginAfterRegistration', ['registration', 'login_after']],
    'invitationsEnabled' => ['invitationsEnabled', ['invitations', 'enabled']],
    'invitationLocksEmail' => ['invitationLocksEmail', ['invitations', 'lock_email']],
    'invitationReplacesPending' => ['invitationReplacesPending', ['invitations', 'replace_pending']],
    'invitationAllowsExistingEmail' => ['invitationAllowsExistingEmail', ['invitations', 'allow_existing_email']],
    'verifiesEmailOnEmailLogin' => ['verifiesEmailOnEmailLogin', ['verification', 'verify_on_email_login']],
    'emailChangeEnabled' => ['emailChangeEnabled', ['email_change', 'enabled']],
    'emailChangeNotifiesOldAddress' => ['emailChangeNotifiesOldAddress', ['email_change', 'notify_old']],
    'emailChangeRequiresReauthentication' => ['emailChangeRequiresReauthentication', ['email_change', 'require_reauthentication']],
    'magicLinkSameDevice' => ['magicLinkSameDevice', ['magic_link', 'same_device']],
    'passwordResetEnabled' => ['passwordResetEnabled', ['passwords', 'reset', 'enabled']],
    'loginAfterPasswordReset' => ['loginAfterPasswordReset', ['passwords', 'reset', 'login_after']],
    'passwordChangeEnabled' => ['passwordChangeEnabled', ['passwords', 'change', 'enabled']],
    'rehashesPasswordsOnLogin' => ['rehashesPasswordsOnLogin', ['passwords', 'rehash_on_login']],
    'passwordRequiresLetters' => ['passwordRequiresLetters', ['passwords', 'policy', 'letters']],
    'passwordRequiresMixedCase' => ['passwordRequiresMixedCase', ['passwords', 'policy', 'mixed_case']],
    'passwordRequiresNumbers' => ['passwordRequiresNumbers', ['passwords', 'policy', 'numbers']],
    'passwordRequiresSymbols' => ['passwordRequiresSymbols', ['passwords', 'policy', 'symbols']],
    'passwordMustNotContainIdentifier' => ['passwordMustNotContainIdentifier', ['passwords', 'policy', 'not_identifier']],
    'breachCheckEnabled' => ['breachCheckEnabled', ['passwords', 'policy', 'uncompromised', 'enabled']],
    'breachCheckFailsClosed' => ['breachCheckFailsClosed', ['passwords', 'policy', 'uncompromised', 'fail_closed']],
    'lockoutEnabled' => ['lockoutEnabled', ['lockout', 'enabled']],
    'passwordResetUnlocks' => ['passwordResetUnlocks', ['lockout', 'reset_unlocks']],
    'reauthenticationRequiresSecondFactorWhenEnrolled' => ['reauthenticationRequiresSecondFactorWhenEnrolled', ['reauthentication', 'require_second_factor_when_enrolled']],
    'freshLoginCountsAsReauthentication' => ['freshLoginCountsAsReauthentication', ['reauthentication', 'fresh_login_counts']],
    'activityEnabled' => ['activityEnabled', ['activity', 'enabled']],
    'newDeviceDetectionEnabled' => ['newDeviceDetectionEnabled', ['activity', 'new_device', 'enabled']],
    'newDeviceSkipsFirstLogin' => ['newDeviceSkipsFirstLogin', ['activity', 'new_device', 'skip_first_login']],
    'storesLocaleOnRegistration' => ['storesLocaleOnRegistration', ['locale', 'store_on_registration']],
    'fillsLocaleOnLogin' => ['fillsLocaleOnLogin', ['locale', 'fill_on_login']],
    'timezonesEnabled' => ['timezonesEnabled', ['locale', 'timezone']],
    'routesEnabled' => ['routesEnabled', ['routes', 'enabled']],
    'invitationManagementRoutes' => ['invitationManagementRoutes', ['routes', 'invitations_management']],
]);

dataset('auth env switches', [
    '"1"' => ['1', true],
    '"on"' => ['on', true],
    '"yes"' => ['yes', true],
    '"true"' => ['true', true],
    '"0"' => ['0', false],
    '"off"' => ['off', false],
    '"no"' => ['no', false],
    '"false"' => ['false', false],
]);

/**
 * @param  list<string>  $path
 * @return array<string, mixed>
 */
function nestedSetting(array $path, mixed $value): array
{
    foreach (array_reverse($path) as $segment) {
        $value = [$segment => $value];
    }

    /** @var array<string, mixed> $value */
    return $value;
}

it('reads the login method switches from an env string', function (string $value, bool $on): void {
    $guard = guardConfig(['login' => [
        'password' => $value,
        'magic_link' => $value,
        'email_otp' => $value,
        'passkey' => $value,
    ]]);

    foreach ([LoginMethod::Password, LoginMethod::MagicLink, LoginMethod::EmailOtp, LoginMethod::Passkey] as $method) {
        expect($guard->loginMethodEnabled($method))->toBe($on);
    }
})->with('auth env switches');

it('reads every boolean guard setting from an env string', function (string $accessor, array $path): void {
    foreach (['on' => true, '1' => true, 'yes' => true, 'off' => false, '0' => false, 'no' => false] as $value => $on) {
        $guard = guardConfig(nestedSetting($path, (string) $value));

        expect($guard->{$accessor}())->toBe($on, "{$accessor}() with '{$value}'");
    }
})->with('boolean guard settings');

it('throws naming the key for an unrecognised switch value (strict config)', function (): void {
    $guard = guardConfig(['login' => ['password' => 'maybe']]);

    expect(fn (): bool => $guard->loginMethodEnabled(LoginMethod::Password))
        ->toThrow(AuthenticationMisconfigured::class, 'Configuration value [authentication.guards.users.login.password] must be a boolean (true/false, 1/0, on/off or yes/no), [maybe] given.');
});

it('names every switch by the very offset chain it reads (strict config)', function (): void {
    $source = (string) file_get_contents(__DIR__.'/../../src/Guards/GuardConfig.php');

    preg_match_all('/\$this->(?:flag|choice)\(\$this->settings((?:\[\x27[a-z_]+\x27\])+) \?\? null, \x27([a-z_.]+)\x27/', $source, $reads, PREG_SET_ORDER);

    // Pinned: every switch leaf (51 on/off + 2 two-way), so an empty parse cannot pass.
    expect($reads)->toHaveCount(53);

    foreach ($reads as [, $chain, $key]) {
        expect(str_replace(["']['", "['", "']"], ['.', '', ''], $chain))->toBe($key);
    }
});

it('refuses a typo in every boolean guard setting, naming its key (strict config)', function (string $accessor, array $path): void {
    $key = 'authentication.guards.clients.'.implode('.', $path);

    foreach (['disabled', 'maybe', ['on']] as $junk) {
        $guard = guardConfig(nestedSetting($path, $junk), 'clients');

        expect(fn (): mixed => $guard->{$accessor}())->toThrow(AuthenticationMisconfigured::class, "[{$key}]");
    }
})->with('boolean guard settings');

it('reads an absent or null switch as its default (strict config)', function (): void {
    $guard = new GuardConfig('users', ['model' => User::class, 'login' => ['password' => null]]);

    expect($guard->loginMethodEnabled(LoginMethod::Password))->toBeTrue()
        ->and($guard->loginMethodEnabled(LoginMethod::MagicLink))->toBeFalse()
        ->and($guard->routesEnabled())->toBeFalse()
        ->and($guard->lowercasesIdentifiers())->toBeTrue()
        ->and($guard->riskDenialIsUniform())->toBeTrue();
});

it('reads a two-way string switch strictly (strict config)', function (string $accessor, array $path, string $on, string $off): void {
    expect(guardConfig(nestedSetting($path, $on))->{$accessor}())->toBeTrue()
        ->and(guardConfig(nestedSetting($path, $off))->{$accessor}())->toBeFalse();

    $key = 'authentication.guards.users.'.implode('.', $path);

    foreach ([ucfirst($on), 'lower', true] as $junk) {
        $guard = guardConfig(nestedSetting($path, $junk));

        expect(fn (): bool => $guard->{$accessor}())->toThrow(AuthenticationMisconfigured::class, "{$key} must be {$on} or {$off}.");
    }
})->with([
    'identifier.normalize' => ['lowercasesIdentifiers', ['identifier', 'normalize'], 'lowercase', 'none'],
    'risk.deny_response' => ['riskDenialIsUniform', ['risk', 'deny_response'], 'uniform', 'explicit'],
]);

it('fails a guard with a typo in any switch when it resolves, not mid-flow (strict config)', function (string $accessor, array $path): void {
    $this->configureGuard('users', [implode('.', $path) => 'disabled']);

    $problems = ConfigValidation::problems(app(GuardRegistry::class)->all()['users'], app(GuardRegistry::class));

    expect(implode("\n", $problems))->toContain('[authentication.guards.users.'.implode('.', $path).']');
})->with('boolean guard settings');

it('fails a guard with a typo in a string switch when it resolves (strict config)', function (string $key): void {
    $this->configureGuard('users', [$key => 'typo']);

    expect(fn () => app(GuardRegistry::class)->get('users'))
        ->toThrow(AuthenticationMisconfigured::class, "authentication.guards.users.{$key} must be");
})->with(['identifier.normalize', 'risk.deny_response']);

it('reads a typo in a switch the password gate hides (strict config)', function (string $key, string $accessor): void {
    $guard = guardConfig(['login' => ['password' => false], ...nestedSetting(explode('.', $key), 'disabled')]);

    expect(fn (): bool => $guard->{$accessor}())->toThrow(AuthenticationMisconfigured::class, "[authentication.guards.users.{$key}]");
})->with([
    'registration.require_password' => ['registration.require_password', 'registrationRequiresPassword'],
    'passwords.reset.enabled' => ['passwords.reset.enabled', 'passwordResetEnabled'],
]);

it('lets the doctor report a switch typo instead of crashing (strict config)', function (): void {
    $this->configureGuard('users', ['login.password' => false, 'login.magic_link' => true, 'passwords.reset.enabled' => 'disabled']);

    $this->artisan('authentication:check', ['guard' => 'users'])
        ->expectsOutputToContain('authentication.guards.users.passwords.reset.enabled')
        ->assertFailed();
});

it('reports env-string switches in the about section the way the guard reads them', function (string $value, bool $on): void {
    $this->configureGuard('users', [
        'login.magic_link' => $value,
        'passwords.policy.uncompromised.enabled' => $value,
        'routes.enabled' => $value,
    ]);

    $about = AboutSection::data();

    expect(str_contains($about['Login methods'], LoginMethod::MagicLink->value))->toBe($on)
        ->and($about['Breach check'])->toBe($on ? 'ON' : 'OFF')
        ->and($about['Routes'])->toBe($on ? 'ON' : 'OFF');
})->with('auth env switches');

it('warns about an env-string reset switch the way the guard reads it', function (string $value, bool $on): void {
    $this->configureGuard('users', ['login.password' => 'off', 'passwords.reset.enabled' => $value]);

    $warnings = implode("\n", ConfigValidation::warnings(app(GuardRegistry::class)->get('users')));

    expect(str_contains($warnings, 'passwords.reset.enabled is ignored'))->toBe($on);
})->with('auth env switches');

/**
 * End to end through the shipped config file: a `(bool) env(...)` cast there turns "off"
 * into true before the guard can read it.
 */
it('honours env-string switches through the shipped config file', function (string $value, bool $on): void {
    $keys = [
        'AUTHENTICATION_LOGIN_PASSWORD',
        'AUTHENTICATION_LOGIN_MAGIC_LINK',
        'AUTHENTICATION_LOGIN_EMAIL_OTP',
        'AUTHENTICATION_LOGIN_PASSKEY',
        'AUTHENTICATION_PASSWORD_BREACH_CHECK',
    ];

    foreach ($keys as $key) {
        $_SERVER[$key] = $value;
    }

    try {
        /** @var array{defaults: array<string, mixed>} $shipped */
        $shipped = require __DIR__.'/../../config/authentication.php';
    } finally {
        foreach ($keys as $key) {
            unset($_SERVER[$key]);
        }
    }

    $guard = new GuardConfig('users', [...$shipped['defaults'], 'model' => 'App\\Models\\User']);

    expect($guard->loginMethodEnabled(LoginMethod::Password))->toBe($on)
        ->and($guard->loginMethodEnabled(LoginMethod::MagicLink))->toBe($on)
        ->and($guard->loginMethodEnabled(LoginMethod::EmailOtp))->toBe($on)
        ->and($guard->loginMethodEnabled(LoginMethod::Passkey))->toBe($on)
        ->and($guard->breachCheckEnabled())->toBe($on);
})->with('auth env switches');
