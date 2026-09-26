<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use Throwable;

/**
 * The `php artisan about` section. Names, modes and ON/OFF flags only — never a key, a
 * secret or a URL that could carry one.
 */
final class AboutSection
{
    /**
     * @return array<string, string>
     */
    public static function data(): array
    {
        $registry = app(GuardRegistry::class);
        $hasher = app(SecretHasher::class);
        $data = [
            'Guards' => implode(', ', $registry->names()) ?: 'NONE',
            'Default guard' => $registry->defaultGuard(),
            'Hash key' => $hasher->usesDerivedKey() ? 'DERIVED' : 'SET',
            'Access-token revoker' => self::revoker() instanceof JwtAccessTokenRevoker ? 'BOUND' : 'NONE',
        ];

        try {
            $guard = $registry->get();
        } catch (Throwable) {
            return [...$data, 'Status' => 'MISCONFIGURED (run authentication:check)'];
        }

        $methods = array_filter(
            [LoginMethod::Password, LoginMethod::MagicLink, LoginMethod::EmailOtp, LoginMethod::Passkey],
            static fn (LoginMethod $method): bool => $guard->loginMethodEnabled($method),
        );

        return [
            ...$data,
            'Login methods' => implode(', ', array_map(static fn (LoginMethod $method): string => $method->value, $methods)),
            '2FA' => $guard->twoFactorMode()->value,
            'Passkeys' => $guard->passkeyMode()->value,
            'Registration' => $guard->registrationMode()->value,
            'Verification' => $guard->verificationMode()->value,
            'Routes' => $guard->routesEnabled() ? 'ON' : 'OFF',
            'Notification delivery' => $guard->notificationDelivery()->value,
            'Breach check' => $guard->breachCheckEnabled() ? 'ON' : 'OFF',
            'Audience' => self::audience($guard->laravelGuard()),
        ];
    }

    /**
     * Resolved behind the contract type on purpose: the binding is swapped at boot.
     */
    public static function revoker(): AccessTokenRevoker
    {
        return app()->make(AccessTokenRevoker::class);
    }

    private static function audience(string $guard): string
    {
        try {
            return Jwt::audienceFor($guard) !== '' ? 'SET' : 'MISSING';
        } catch (Throwable) {
            return 'NOT A JWT GUARD';
        }
    }
}
