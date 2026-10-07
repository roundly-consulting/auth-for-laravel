<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
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
    // `allowed` + mode off is accepted (it only permits a passkey step, and there are none).
    'second factor required with passkeys off' => ['clients', ['passkeys.second_factor' => 'required'], 'passkeys.mode is off'],
    'second factor required when enrolled with passkeys off' => ['clients', ['passkeys.second_factor' => 'required_when_enrolled'], 'passkeys.mode is off'],
    'no login method' => ['clients', ['login.magic_link' => false], 'at least one login method'],
    'invite only without invitations' => ['clients', ['registration.mode' => 'invite_only'], 'invitations.enabled'],
    'forced enrolment without verification' => ['users', ['two_factor.mode' => 'required', 'verification.mode' => 'off'], 'verification.mode is off'],
    'invalid enum' => ['users', ['verification.channel' => 'pigeon'], 'verification.channel'],
    'not a jwt guard' => ['users', ['laravel_guard' => 'web'], 'is not configured with the jwt driver'],
    'shared laravel guard' => ['clients', ['laravel_guard' => 'users'], 'laravel_guard must differ'],
    'shared model' => ['clients', ['model' => User::class], 'shares its morph class'],
    'invalidation scope typo' => ['users', ['invalidation.password_changed' => 'other'], 'invalidation.password_changed'],
    'risk reaction typo' => ['users', ['risk.reactions.high' => 'block'], 'risk.reactions.high'],
    'sensitive action typo' => ['users', ['reauthentication.required_for' => ['enable_two_factor', 'disable_2fa']], 'reauthentication.required_for'],
    'reauthentication method typo' => ['users', ['reauthentication.methods' => ['password', 'sms']], 'reauthentication.methods'],
    'registration rules class' => ['users', ['registration.rules' => stdClass::class], 'registration.rules'],
    'account creator class' => ['users', ['registration.creator' => stdClass::class], 'registration.creator'],
    'risk assessor class' => ['users', ['risk.assessor' => stdClass::class], 'risk.assessor'],
    'claims resolver class' => ['users', ['tokens.claims_resolver' => 'App\\Missing\\Resolver'], 'tokens.claims_resolver'],
    'notification class' => ['users', ['notifications.classes.new_device' => stdClass::class], 'notifications.classes.new_device'],
    'account resource class' => ['users', ['resources.account' => stdClass::class], 'resources.account'],
]);

/**
 * Regression (chat review C-2): `AUTHENTICATION_PASSKEYS=off` is a documented env value, but
 * the shipped `second_factor` stays `allowed`, and validation flagged that pair, so every
 * guard on the defaults failed to resolve (every endpoint 500, `authentication:check` exit 1).
 * `allowed` is only a permission; the runtime already treats mode off as second factor off.
 */
it('accepts the shipped config with AUTHENTICATION_PASSKEYS=off', function (): void {
    $_SERVER['AUTHENTICATION_PASSKEYS'] = 'off';
    $_SERVER['AUTHENTICATION_USERS_MODEL'] = User::class;

    try {
        /** @var array{defaults: array<string, mixed>, guards: array<string, mixed>} $shipped */
        $shipped = require __DIR__.'/../../config/authentication.php';
    } finally {
        unset($_SERVER['AUTHENTICATION_PASSKEYS'], $_SERVER['AUTHENTICATION_USERS_MODEL']);
    }

    config()->set('authentication.defaults', $shipped['defaults']);
    config()->set('authentication.guards', $shipped['guards']);
    app(GuardRegistry::class)->flush();

    $registry = app(GuardRegistry::class);

    expect($registry->all()['users']->passkeySecondFactor()->value)->toBe('allowed')
        ->and(ConfigValidation::problems($registry->all()['users'], $registry))->toBe([])
        ->and($registry->get('users')->name())->toBe('users');
});

it('refuses to resolve a guard with a typo before any credential changes', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->configureGuard('users', ['invalidation.password_changed' => 'other']);

    $this->putJson('/users/auth/password', ['current_password' => 'correct-horse-battery', 'password' => 'a-brand-new-passphrase'], bearer($pair))
        ->assertStatus(500)
        ->assertJsonPath('code', 'misconfigured');

    expect(Hash::check('correct-horse-battery', (string) $user->fresh()?->getAttribute('password')))->toBeTrue();
});

it('requires the token version resolver on the jwt guard', function (): void {
    config()->set('jwt.guard.token_version', null);
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('users');
})->throws(AuthenticationMisconfigured::class, 'TokenVersionResolver');

it('requires the denylist check on the jwt guard', function (mixed $value): void {
    config()->set('auth.guards.users.check_denylist', $value);
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('users');
})->throws(AuthenticationMisconfigured::class, 'check_denylist')->with([false, 'false', 'off']);

it('refuses a typo in the jwt guard denylist switch (strict config)', function (): void {
    config()->set('auth.guards.users.check_denylist', 'disabled');
    app(GuardRegistry::class)->flush();

    app(GuardRegistry::class)->get('users');
})->throws(AuthenticationMisconfigured::class, 'Configuration value [auth.guards.users.check_denylist] must be a boolean');

it('names the jwt reason when the jwt guard cannot be resolved', function (): void {
    config()->set('auth.guards.users.token_version', ['not', 'callable']);
    app(GuardRegistry::class)->flush();

    $registry = app(GuardRegistry::class);

    expect(implode("\n", ConfigValidation::problems($registry->all()['users'], $registry)))
        ->toContain('token_version of jwt guard [users] must be an invokable class-string or a closure')
        ->not->toContain('is not configured with the jwt driver');
});

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

it('warns that closed registration also closes invitation acceptance', function (): void {
    $this->configureGuard('users', ['registration.mode' => 'closed']);

    expect(implode("\n", ConfigValidation::warnings(app(GuardRegistry::class)->all()['users'])))
        ->toContain('registration.mode is closed, so invitations cannot be accepted');
});

it('keeps the client fixture a distinct guard model', function (): void {
    expect((new Client)->getMorphClass())->not->toBe((new User)->getMorphClass());
});
