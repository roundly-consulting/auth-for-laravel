<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\ConfigValidation;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\PlainAccount;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('accepts the test configuration', function (): void {
    $registry = app(GuardRegistry::class);

    expect(ConfigValidation::problems($registry->all()['users'], $registry))->toBe([])
        ->and(ConfigValidation::problems($registry->all()['clients'], $registry))->toBe([]);
});

it('reports each misconfiguration with its exact key', function (string $guard, array $settings, string $message): void {
    $this->configureGuard($guard, $settings);

    $registry = app(GuardRegistry::class);

    expect(implode("\n", ConfigValidation::problems($registry->all()[$guard], $registry)))->toContain($message)
        ->and(fn () => $registry->get($guard))->toThrow(AuthenticationMisconfigured::class);
})->with([
    'model missing' => ['users', ['model' => null], 'authentication.guards.users.model'],
    'model not an account' => ['users', ['model' => stdClass::class], 'must be an Eloquent model implementing'],
    '2fa without the contract' => ['clients', ['model' => PlainAccount::class, 'two_factor.mode' => 'optional', 'passkeys.mode' => 'off'], 'two_factor.mode is on'],
    'passkeys without the contract' => ['clients', ['model' => PlainAccount::class, 'passkeys.mode' => 'optional'], 'passkeys are on'],
    'passkey login with passkeys off' => ['clients', ['login.passkey' => true], 'passkeys.mode is off'],
    'second factor with passkeys off' => ['clients', ['passkeys.second_factor' => 'allowed'], 'passkeys.mode is off'],
    'no login method' => ['clients', ['login.magic_link' => false], 'at least one login method'],
    'invite only without invitations' => ['clients', ['registration.mode' => 'invite_only'], 'invitations.enabled'],
    'forced enrolment without verification' => ['users', ['two_factor.mode' => 'required', 'verification.mode' => 'off'], 'verification.mode is off'],
    'invalid enum' => ['users', ['verification.channel' => 'pigeon'], 'verification.channel'],
    'not a jwt guard' => ['users', ['laravel_guard' => 'web'], 'is not an auth.guards entry using the `jwt` driver'],
    'shared laravel guard' => ['clients', ['laravel_guard' => 'users'], 'laravel_guard must differ'],
    'shared model' => ['clients', ['model' => User::class], 'shares its morph class'],
]);

it('requires the token version resolver on the jwt guard', function (): void {
    config()->set('jwt.guard.token_version', null);
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('users');
})->throws(AuthenticationMisconfigured::class, 'TokenVersionResolver');

it('requires distinct audiences once there are several guards', function (): void {
    config()->set('auth.guards.clients.audience', 'app-users');
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('clients');
})->throws(AuthenticationMisconfigured::class, 'share one audience');

it('requires key types to agree across the shared morph columns', function (): void {
    config()->set('passkeys.key_type', 'uuid');
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('users');
})->throws(AuthenticationMisconfigured::class, 'passkeys.key_type');

it('requires the model key to match the key type', function (): void {
    config()->set('authentication.key_type', 'uuid');
    config()->set('passkeys.key_type', 'uuid');
    config()->set('refresh-tokens.key_type', 'uuid');
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('users');
})->throws(AuthenticationMisconfigured::class, 'has bigint keys');

it('warns about suspicious but valid combinations', function (): void {
    $this->configureGuard('clients', ['notifications.delivery' => 'sync', 'passwords.reset.enabled' => true]);

    expect(ConfigValidation::warnings(app(GuardRegistry::class)->all()['clients']))
        ->toHaveCount(2)
        ->and(ConfigValidation::warnings(app(GuardRegistry::class)->all()['users']))->toHaveCount(1);
});

it('keeps the client fixture a distinct guard model', function (): void {
    expect((new Client)->getMorphClass())->not->toBe((new User)->getMorphClass());
});
