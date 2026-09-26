<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\PasskeySecondFactor;
use RoundlyConsulting\Auth\Enums\RegistrationMode;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Every rule a guard's configuration must satisfy, checked when the guard is first
 * resolved (the first problem throws, naming the exact key) and listed in full by
 * `authentication:check`.
 */
final class ConfigValidation
{
    /**
     * @throws AuthenticationMisconfigured
     */
    public static function assertValid(GuardConfig $guard, GuardRegistry $registry): void
    {
        $problems = self::problems($guard, $registry);

        if ($problems !== []) {
            throw AuthenticationMisconfigured::because($problems[0]);
        }
    }

    /**
     * @return list<string>
     */
    public static function problems(GuardConfig $guard, GuardRegistry $registry): array
    {
        $problems = [];
        $prefix = "authentication.guards.{$guard->name()}";

        try {
            $model = $guard->model();
        } catch (AuthenticationMisconfigured $e) {
            return [$e->getMessage()];
        }

        try {
            self::policyProblems($guard, $model, $prefix, $problems);
        } catch (AuthenticationMisconfigured $e) {
            $problems[] = $e->getMessage();
        }

        self::jwtProblems($guard, $prefix, $problems);
        self::keyTypeProblems($model, $prefix, $problems);
        self::crossGuardProblems($guard, $registry, $prefix, $problems);

        return $problems;
    }

    /**
     * Sane-but-suspicious combinations the doctor reports without failing.
     *
     * @return list<string>
     */
    public static function warnings(GuardConfig $guard): array
    {
        $warnings = [];
        $prefix = "authentication.guards.{$guard->name()}";

        try {
            $settings = $guard->toArray();

            if (! $guard->loginMethodEnabled(LoginMethod::Password) && (bool) ($settings['passwords']['reset']['enabled'] ?? false)) {
                $warnings[] = "{$prefix}.passwords.reset.enabled is ignored because login.password is off.";
            }

            if ($guard->notificationDelivery()->value === 'sync') {
                $warnings[] = "{$prefix}.notifications.delivery = sync makes known-account responses measurably slower (timing enumeration); prefer after_response or queue.";
            }
        } catch (AuthenticationMisconfigured) {
            // Reported by problems().
        }

        return $warnings;
    }

    /**
     * @param  class-string<Model&Account>  $model
     * @param  list<string>  $problems
     */
    private static function policyProblems(GuardConfig $guard, string $model, string $prefix, array &$problems): void
    {
        if ($guard->twoFactorMode() !== TwoFactorMode::Off && ! is_subclass_of($model, TwoFactorAuthenticatable::class)) {
            $problems[] = "{$prefix}.two_factor.mode is on, but {$model} does not implement ".TwoFactorAuthenticatable::class.'.';
        }

        $usesPasskeys = $guard->passkeyMode() !== PasskeyMode::Off || $guard->loginMethodEnabled(LoginMethod::Passkey);

        if ($usesPasskeys && ! is_subclass_of($model, HasPasskeys::class)) {
            $problems[] = "{$prefix}: passkeys are on, but {$model} does not implement ".HasPasskeys::class.'.';
        }

        if ($guard->passkeyMode() === PasskeyMode::Off
            && ($guard->loginMethodEnabled(LoginMethod::Passkey) || $guard->passkeySecondFactor() !== PasskeySecondFactor::Off)) {
            $problems[] = "{$prefix}.passkeys.mode is off, so login.passkey must be false and passkeys.second_factor must be off.";
        }

        $anyLogin = array_filter(
            [LoginMethod::Password, LoginMethod::MagicLink, LoginMethod::EmailOtp, LoginMethod::Passkey],
            static fn (LoginMethod $method): bool => $guard->loginMethodEnabled($method),
        );

        if ($anyLogin === []) {
            $problems[] = "{$prefix}.login: at least one login method must be enabled.";
        }

        if ($guard->registrationMode() === RegistrationMode::InviteOnly && ! $guard->invitationsEnabled()) {
            $problems[] = "{$prefix}.registration.mode is invite_only, so invitations.enabled must be true.";
        }

        $forcesEnrolment = $guard->twoFactorMode() === TwoFactorMode::Required
            || $guard->passkeyMode() === PasskeyMode::Required
            || $guard->passkeySecondFactor() === PasskeySecondFactor::Required;

        if ($forcesEnrolment && $guard->enrolmentRequiresVerifiedEmail() && $guard->verificationMode() === EmailVerificationMode::Off) {
            $problems[] = "{$prefix}: a factor enrolment is forced and challenge.enrolment_requires_verified_email is on, but verification.mode is off — password accounts could never satisfy it.";
        }

        // Resolve every remaining enum-backed leaf so a typo fails here, not mid-login.
        $guard->registrationMode();
        $guard->verificationChannel();
        $guard->identifierStorage();
        $guard->notificationDelivery();
    }

    /**
     * @param  list<string>  $problems
     */
    private static function jwtProblems(GuardConfig $guard, string $prefix, array &$problems): void
    {
        try {
            $settings = Jwt::guardSettings($guard->laravelGuard());
        } catch (JwtMisconfigured) {
            $problems[] = "{$prefix}.laravel_guard [{$guard->laravelGuard()}] is not an auth.guards entry using the `jwt` driver.";

            return;
        }

        $resolver = $settings->tokenVersion;

        if (! is_string($resolver) || ! is_a($resolver, TokenVersionResolver::class, true)) {
            $problems[] = "The jwt guard [{$guard->laravelGuard()}] must use ".TokenVersionResolver::class.' as its token_version (jwt.guard.token_version or auth.guards.'.$guard->laravelGuard().'.token_version); without it invalidation revokes nothing.';
        }

        if (! $settings->checkDenylist) {
            $problems[] = "The jwt guard [{$guard->laravelGuard()}] must keep check_denylist on (jwt.guard.check_denylist or auth.guards.{$guard->laravelGuard()}.check_denylist); logout, session revocation and every token denial rely on it.";
        }
    }

    /**
     * @param  class-string<Model&Account>  $model
     * @param  list<string>  $problems
     */
    private static function keyTypeProblems(string $model, string $prefix, array &$problems): void
    {
        $keyType = KeyType::fromConfig('authentication.key_type');

        foreach (['passkeys.key_type', 'refresh-tokens.key_type'] as $key) {
            if (config($key) !== null && KeyType::fromConfig($key) !== $keyType) {
                $problems[] = "authentication.key_type ({$keyType->value}) must equal {$key} — the morph columns are shared.";
            }
        }

        $modelKeyType = self::modelKeyType(new $model);

        if ($modelKeyType !== $keyType) {
            $problems[] = "{$prefix}.model {$model} has {$modelKeyType->value} keys, but authentication.key_type is {$keyType->value}.";
        }
    }

    /**
     * @param  list<string>  $problems
     */
    private static function crossGuardProblems(GuardConfig $guard, GuardRegistry $registry, string $prefix, array &$problems): void
    {
        $all = $registry->all();

        if (count($all) < 2) {
            return;
        }

        foreach ($all as $name => $other) {
            if ($name === $guard->name()) {
                continue;
            }

            if ($other->laravelGuard() === $guard->laravelGuard()) {
                $problems[] = "{$prefix}.laravel_guard must differ from guard [{$name}]'s.";

                continue;
            }

            $otherModel = $other->configuredModel();

            if ($otherModel !== null && is_subclass_of($otherModel, Model::class)
                && (new $otherModel)->getMorphClass() === (new ($guard->model()))->getMorphClass()) {
                $problems[] = "{$prefix}.model shares its morph class with guard [{$name}]; guards must use distinct models (a role on one table is authorization, not a guard).";
            }

            try {
                if (Jwt::audienceFor($other->laravelGuard()) === Jwt::audienceFor($guard->laravelGuard())) {
                    $problems[] = "The jwt guards of [{$guard->name()}] and [{$name}] share one audience; give each auth.guards entry its own `audience`, or one guard's tokens authenticate on the other.";
                }
            } catch (JwtMisconfigured) {
                // Reported for that guard itself.
            }
        }
    }

    private static function modelKeyType(Model $model): KeyType
    {
        $traits = class_uses_recursive($model);

        return match (true) {
            in_array(HasUuids::class, $traits, true) => KeyType::Uuid,
            in_array(HasUlids::class, $traits, true) => KeyType::Ulid,
            $model->getKeyType() === 'int' => KeyType::BigInt,
            default => KeyType::Uuid,
        };
    }
}
