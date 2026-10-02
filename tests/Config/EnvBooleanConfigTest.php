<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AboutSection;
use RoundlyConsulting\Auth\Support\ConfigValidation;

/**
 * Regression (env-boolean sweep): every guard switch was read with `(bool)`, and the
 * env-backed ones (`login.*`, `passwords.policy.uncompromised.enabled`) were cast
 * `(bool) env(...)` in the config file. env() only converts "true"/"false", so
 * `AUTHENTICATION_LOGIN_PASSWORD=off` was cast to TRUE — password login stayed open — and
 * `AUTHENTICATION_PASSWORD_BREACH_CHECK=no` kept the breach check on. Every switch (and the
 * `about` rows built from them) now reads the value as a boolean.
 */
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
})->with([
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

it('falls back to the switch default for an unrecognised value', function (): void {
    $guard = guardConfig([
        'login' => ['password' => 'maybe', 'magic_link' => 'maybe'],
        'routes' => ['enabled' => ['on']],
    ]);

    expect($guard->loginMethodEnabled(LoginMethod::Password))->toBeTrue()
        ->and($guard->loginMethodEnabled(LoginMethod::MagicLink))->toBeFalse()
        ->and($guard->routesEnabled())->toBeFalse();
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
