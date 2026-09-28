<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Account\DisableAccount;
use RoundlyConsulting\Auth\Actions\Account\EnableAccount;
use RoundlyConsulting\Auth\Actions\Account\LockAccount;
use RoundlyConsulting\Auth\Actions\Account\SendReauthenticationCode;
use RoundlyConsulting\Auth\Actions\Account\UnlockAccount;
use RoundlyConsulting\Auth\Actions\Account\UpdateLocale;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailChange;
use RoundlyConsulting\Auth\Actions\Email\RequestEmailVerification;
use RoundlyConsulting\Auth\Actions\Email\SendEmailVerification;
use RoundlyConsulting\Auth\Actions\Passkeys\RegisterPasskey;
use RoundlyConsulting\Auth\Actions\Passkeys\RemovePasskey;
use RoundlyConsulting\Auth\Actions\Passkeys\RenamePasskey;
use RoundlyConsulting\Auth\Actions\Passwords\ChangePassword;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\Actions\TwoFactor\ConfirmTwoFactorEnrolment;
use RoundlyConsulting\Auth\Actions\TwoFactor\DisableTwoFactor;
use RoundlyConsulting\Auth\Actions\TwoFactor\RegenerateRecoveryCodes;
use RoundlyConsulting\Auth\Actions\TwoFactor\StartTwoFactorEnrolment;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\EmailChangeData;
use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

/**
 * Regression: every account-taking action refuses another guard's account BEFORE it
 * writes anything. The `users` guard is handed a `Client` (the `clients` guard's model);
 * each case asserts the refusal and that nothing about the client changed.
 */
function foreignToken(): CurrentToken
{
    return new CurrentToken('foreign-jti', CarbonImmutable::now()->addHour());
}

it('refuses a foreign account before writing a password (SetPassword)', function (): void {
    $client = Client::factory()->create();

    expect(fn () => app(SetPassword::class)->execute('users', $client, 'a-brand-new-passphrase'))
        ->toThrow(AuthenticationMisconfigured::class);

    expect(Hash::check('correct-horse-battery', (string) $client->fresh()?->password))->toBeTrue();
});

it('refuses a foreign account before writing a password (ChangePassword)', function (): void {
    $client = Client::factory()->create();

    expect(fn () => app(ChangePassword::class)->execute('users', $client, new ChangePasswordData('correct-horse-battery', 'a-brand-new-passphrase', foreignToken(), sessionContext())))
        ->toThrow(AuthenticationMisconfigured::class);

    expect(Hash::check('correct-horse-battery', (string) $client->fresh()?->password))->toBeTrue();
});

it('refuses a foreign account before disabling its two-factor', function (): void {
    $client = Client::factory()->create();
    enableTotp($client);

    expect(fn () => app(DisableTwoFactor::class)->execute('users', $client, foreignToken(), sessionContext()))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->hasTwoFactorEnabled())->toBeTrue();
});

it('refuses a foreign account before confirming its two-factor enrolment', function (): void {
    $client = Client::factory()->create();
    $setup = TwoFactor::for($client)->start();

    expect(fn () => app(ConfirmTwoFactorEnrolment::class)->execute('users', $client, totpCode($setup->secret), foreignToken(), sessionContext()))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->hasTwoFactorEnabled())->toBeFalse();
});

it('refuses a foreign account before regenerating its recovery codes', function (): void {
    $client = Client::factory()->create();
    enableTotp($client);
    $before = $client->fresh()?->getAttributes()['two_factor_recovery_codes'];

    expect(fn () => app(RegenerateRecoveryCodes::class)->execute('users', $client, foreignToken(), sessionContext()))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->getAttributes()['two_factor_recovery_codes'])->toBe($before);
});

it('refuses a foreign account before starting a two-factor enrolment', function (): void {
    $client = Client::factory()->create();

    expect(fn () => app(StartTwoFactorEnrolment::class)->execute('users', $client))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->hasPendingTwoFactor())->toBeFalse();
});

it('refuses a foreign account before registering a passkey', function (): void {
    $client = Client::factory()->create();
    $response = VirtualAuthenticator::es256()->register(Passkeys::for($client)->registrationOptions());

    expect(fn () => app(RegisterPasskey::class)->execute('users', $client, $response, 'Laptop', foreignToken(), sessionContext()))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->passkeys()->count())->toBe(0);
});

it('refuses a foreign account before removing a passkey', function (): void {
    $client = Client::factory()->create();
    $passkey = addPasskey($client);

    expect(fn () => app(RemovePasskey::class)->execute('users', $client, (int) $passkey->getKey(), foreignToken(), sessionContext()))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->passkeys()->count())->toBe(1);
});

it('refuses a foreign account before renaming a passkey', function (): void {
    $client = Client::factory()->create();
    $passkey = addPasskey($client);
    $name = $passkey->name;

    expect(fn () => app(RenamePasskey::class)->execute('users', $client, (int) $passkey->getKey(), 'Renamed'))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($passkey->fresh()?->name)->toBe($name);
});

it('refuses a foreign account before disabling it', function (): void {
    $client = Client::factory()->create();

    expect(fn () => app(DisableAccount::class)->execute('users', $client, 'fraud'))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->isDisabled())->toBeFalse();
});

it('refuses a foreign account before enabling it', function (): void {
    $client = Client::factory()->disabled()->create();

    expect(fn () => app(EnableAccount::class)->execute('users', $client))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->isDisabled())->toBeTrue();
});

it('refuses a foreign account before locking it', function (): void {
    $client = Client::factory()->create();

    expect(fn () => app(LockAccount::class)->execute('users', $client, 60))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->isLocked())->toBeFalse();
});

it('refuses a foreign account before unlocking it', function (): void {
    $client = Client::factory()->create(['locked_until' => now()->addHour()]);

    expect(fn () => app(UnlockAccount::class)->execute('users', $client))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->isLocked())->toBeTrue();
});

it('refuses a foreign account before updating its locale', function (): void {
    $client = Client::factory()->create();

    expect(fn () => app(UpdateLocale::class)->execute('users', $client, new LocaleData('en')))
        ->toThrow(AuthenticationMisconfigured::class);

    expect($client->fresh()?->accountLocale())->toBeNull();
});

it('refuses a foreign account before mailing it anything', function (Closure $call): void {
    Notification::fake();

    expect(fn () => $call(Client::factory()->unverified()->passwordless()->create()))
        ->toThrow(AuthenticationMisconfigured::class);

    Notification::assertNothingSent();
    expect(Models::oneTimeTokens()->count())->toBe(0);
})->with([
    'email change' => [fn (Client $client) => app(RequestEmailChange::class)->execute('users', $client, new EmailChangeData('new@example.com', sessionContext()))],
    'verification (send)' => [fn (Client $client) => app(SendEmailVerification::class)->execute('users', $client)],
    'verification (request)' => [fn (Client $client) => app(RequestEmailVerification::class)->execute('users', $client, sessionContext())],
    're-authentication code' => [fn (Client $client) => app(SendReauthenticationCode::class)->execute('users', $client, sessionContext())],
]);
