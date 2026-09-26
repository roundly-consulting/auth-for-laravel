<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Auth\AuthenticationServiceProvider;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\TokenVersionResolver;
use RoundlyConsulting\Auth\Testing\InteractsWithAuthentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\Jwt\JwtServiceProvider;
use RoundlyConsulting\Passkeys\PasskeysServiceProvider;
use RoundlyConsulting\Qr\QrServiceProvider;
use RoundlyConsulting\RefreshTokens\RefreshTokensServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;
use RoundlyConsulting\TwoFactor\TwoFactorServiceProvider;

abstract class TestCase extends PackageTestCase
{
    use InteractsWithAuthentication;

    /**
     * @return list<class-string<ServiceProvider>>
     */
    protected function packageProviders(): array
    {
        return [
            CryptoServiceProvider::class,
            JwtServiceProvider::class,
            RefreshTokensServiceProvider::class,
            TwoFactorServiceProvider::class,
            PasskeysServiceProvider::class,
            QrServiceProvider::class,
            AuthenticationServiceProvider::class,
        ];
    }

    /**
     * @return list<class-string<ServiceProvider>|string>
     */
    protected function migrationSources(): array
    {
        return [
            __DIR__.'/Fixtures/database/migrations',
            RefreshTokensServiceProvider::class,
            PasskeysServiceProvider::class,
            AuthenticationServiceProvider::class,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function configBeforeBoot(): array
    {
        return [
            'app.key' => 'base64:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=',
            'app.url' => 'https://app.test',
            'cache.default' => 'array',
            'mail.default' => 'array',
            'queue.default' => 'sync',

            'jwt.private_key_path' => __DIR__.'/Fixtures/keys/jwt-private.pem',
            'jwt.public_key_path' => __DIR__.'/Fixtures/keys/jwt-public.pem',
            'jwt.issuer' => 'https://auth.app.test',
            'jwt.audience' => 'app-users',
            'jwt.denylist.store' => 'array',
            'jwt.guard.token_version' => TokenVersionResolver::class,

            'auth.guards.users' => ['driver' => 'jwt', 'provider' => 'users', 'audience' => 'app-users'],
            'auth.guards.clients' => ['driver' => 'jwt', 'provider' => 'clients', 'audience' => 'app-clients'],
            'auth.providers.users' => ['driver' => 'authentication', 'guard' => 'users'],
            'auth.providers.clients' => ['driver' => 'authentication', 'guard' => 'clients'],

            'passkeys.rp.id' => 'app.test',
            'passkeys.origins' => ['https://app.test'],

            'authentication.guards' => [
                'users' => [
                    'model' => User::class,
                    'login' => ['password' => true, 'magic_link' => true, 'email_otp' => true, 'passkey' => true],
                    'registration' => ['mode' => 'open'],
                    'invitations' => ['enabled' => true],
                    'notifications' => ['delivery' => 'sync', 'frontend_url' => 'https://users.app.test'],
                    'routes' => ['enabled' => true, 'invitations_management' => true],
                ],
                'clients' => [
                    'model' => Client::class,
                    'login' => ['password' => false, 'magic_link' => true],
                    'two_factor' => ['mode' => 'off'],
                    'passkeys' => ['mode' => 'off', 'second_factor' => 'off'],
                    'notifications' => ['delivery' => 'sync'],
                    'routes' => ['enabled' => true],
                ],
            ],
        ];
    }

    /**
     * Change a guard's settings at runtime (actions read config per call; routes were
     * registered at boot).
     *
     * @param  array<string, mixed>  $settings  dotted keys under authentication.guards.<guard>
     */
    protected function configureGuard(string $guard, array $settings): void
    {
        foreach ($settings as $key => $value) {
            config()->set("authentication.guards.{$guard}.{$key}", $value);
        }

        $this->app->make(GuardRegistry::class)->flush();
    }
}
