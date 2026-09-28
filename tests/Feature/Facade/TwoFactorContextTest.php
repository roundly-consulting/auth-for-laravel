<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\TwoFactor\GetTwoFactorStatus;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Events\RecoveryCodesRegenerated;
use RoundlyConsulting\Auth\Events\TwoFactorDisabled;
use RoundlyConsulting\Auth\Events\TwoFactorEnabled;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\TwoFactorAlreadyEnabled;
use RoundlyConsulting\Auth\Exceptions\TwoFactorNotEnabled;
use RoundlyConsulting\Auth\Exceptions\TwoFactorRequired;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

it('enrols the signed-in account and swaps its device to a fresh pair', function (): void {
    Event::fake([TwoFactorEnabled::class]);
    $user = User::factory()->create();
    $pair = issuePair($user);
    $twoFactor = Authentication::guard('users')->twoFactor();

    $setup = $twoFactor->start($user);
    expect($twoFactor->status($user)->pending)->toBeTrue()
        ->and(fn () => $twoFactor->confirm($user, '000000'))->toThrow(InvalidCode::class);

    $tokens = $twoFactor->confirm($user, totpCode($setup->secret), currentTokenOf($pair), sessionContext());

    expect($tokens)->not->toBeNull()
        ->and($twoFactor->status($user)->enabled)->toBeTrue()
        ->and($twoFactor->status($user)->mode)->toBe(TwoFactorMode::Optional)
        ->and(fn () => $twoFactor->start($user))->toThrow(TwoFactorAlreadyEnabled::class);
    Event::assertDispatched(TwoFactorEnabled::class);
});

it('runs admin calls without a current token, keeping no device', function (): void {
    Event::fake([RecoveryCodesRegenerated::class, TwoFactorDisabled::class]);
    $user = User::factory()->create();
    enableTotp($user);
    $pair = issuePair($user);

    $codes = Authentication::twoFactor()->regenerateRecoveryCodes($user);

    expect($codes->codes)->toHaveCount(8)
        ->and($codes->tokens)->toBeNull();

    expect(Authentication::twoFactor()->disable($user))->toBeNull()
        ->and($user->fresh()?->hasTwoFactorEnabled())->toBeFalse()
        ->and(fn () => Authentication::twoFactor()->disable($user))->toThrow(TwoFactorNotEnabled::class)
        ->and(fn () => Authentication::twoFactor()->regenerateRecoveryCodes($user))->toThrow(TwoFactorNotEnabled::class);

    // No device was kept: the session the user held is gone (`others` without a device = `all`).
    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    Event::assertDispatched(RecoveryCodesRegenerated::class);
    Event::assertDispatched(TwoFactorDisabled::class);
});

it('confirms an enrolment from host code without a current token', function (): void {
    $user = User::factory()->create();
    $setup = Authentication::twoFactor()->start($user);

    expect(Authentication::twoFactor()->confirm($user, totpCode($setup->secret)))->toBeNull()
        ->and($user->fresh()?->hasTwoFactorEnabled())->toBeTrue();
});

it('applies the guard mode', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $user = User::factory()->create();
    enableTotp($user);

    expect(fn () => Authentication::twoFactor()->disable($user))->toThrow(TwoFactorRequired::class)
        ->and(fn () => Authentication::guard('clients')->twoFactor()->start(Client::factory()->create()))->toThrow(LoginMethodDisabled::class)
        ->and(fn () => Authentication::guard('clients')->twoFactor()->regenerateRecoveryCodes(Client::factory()->create()))->toThrow(LoginMethodDisabled::class);
});

it('reads the status through the action too', function (): void {
    $user = User::factory()->create();

    expect(app(GetTwoFactorStatus::class)->execute('users', $user))->toEqual(Authentication::twoFactor()->status($user));
});
