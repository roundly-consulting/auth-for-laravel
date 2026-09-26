<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\TwoFactor\DisableTwoFactor;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Exceptions\TwoFactorRequired;
use RoundlyConsulting\Auth\Notifications\TwoFactorDisabledNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
});

it('shows the status', function (): void {
    $user = User::factory()->create();
    enableTotp($user);

    $this->getJson('/users/auth/two-factor', bearer(issuePair($user)))
        ->assertOk()
        ->assertExactJson(['enabled' => true, 'pending' => false, 'recovery_codes_remaining' => 3, 'mode' => 'optional']);
});

it('enables totp and returns the re-issued pair on confirmation', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $secret = $this->postJson('/users/auth/two-factor', [], bearer($pair))->assertOk()->json('secret');

    $this->postJson('/users/auth/two-factor', [], bearer($pair))->assertOk();
    $secret = $user->fresh()?->twoFactorSecret();

    $response = $this->postJson('/users/auth/two-factor/confirm', ['code' => totpCode((string) $secret)], bearer($pair))
        ->assertOk()
        ->assertJsonPath('status', 'enabled')
        ->assertJsonPath('tokens.status', 'authenticated');

    $this->getJson('/users/auth/me', bearer($pair))->assertUnauthorized();
    $this->getJson('/users/auth/me', ['Authorization' => 'Bearer '.$response->json('tokens.access_token')])->assertOk();
    expect(claimsOf($pair)->authMethods())->toBe(['pwd']);
});

it('refuses a wrong confirmation code and a second enrolment', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $this->postJson('/users/auth/two-factor/confirm', ['code' => '123456'], bearer($pair))->assertStatus(422)->assertJsonPath('code', 'invalid_code');

    $this->postJson('/users/auth/two-factor', [], bearer($pair))->assertOk();
    $this->postJson('/users/auth/two-factor/confirm', ['code' => '000000'], bearer($pair))->assertStatus(422);

    enableTotp($user);
    $totpLogin = issuePair($user, amr: [AuthMethodReference::Pwd, AuthMethodReference::Otp, AuthMethodReference::Mfa]);
    $this->postJson('/users/auth/two-factor', [], bearer($totpLogin))->assertStatus(409)->assertJsonPath('code', 'two_factor_already_enabled');
});

it('disables totp and tells the owner', function (): void {
    $user = User::factory()->create();
    enableTotp($user);
    $pair = issuePair($user, amr: [AuthMethodReference::Pwd, AuthMethodReference::Otp, AuthMethodReference::Mfa]);

    $this->deleteJson('/users/auth/two-factor', [], bearer($pair))
        ->assertOk()
        ->assertJsonPath('status', 'disabled')
        ->assertJsonStructure(['tokens' => ['access_token']]);

    expect($user->fresh()?->hasTwoFactorEnabled())->toBeFalse();
    Notification::assertSentTo($user, TwoFactorDisabledNotification::class);
});

it('refuses to disable totp while the guard requires it', function (): void {
    $user = User::factory()->create();
    enableTotp($user);
    $pair = issuePair($user);
    $this->configureGuard('users', ['two_factor.mode' => 'required']);

    $action = app(DisableTwoFactor::class);

    expect(fn () => $action->execute('users', $user, CurrentToken::fromClaims(claimsOf($pair)), sessionContext()))
        ->toThrow(TwoFactorRequired::class);
});

it('regenerates recovery codes and keeps the caller signed in', function (): void {
    $this->configureGuard('users', ['invalidation.two_factor_changed' => 'none']);
    $user = User::factory()->create();
    enableTotp($user);
    $pair = issuePair($user, amr: [AuthMethodReference::Pwd, AuthMethodReference::Otp, AuthMethodReference::Mfa]);

    $this->postJson('/users/auth/two-factor/recovery-codes', [], bearer($pair))
        ->assertOk()
        ->assertJsonCount(8, 'recovery_codes')
        ->assertJsonPath('tokens', null);

    $this->getJson('/users/auth/me', bearer($pair))->assertOk();
});

it('is absent on a guard without two-factor', function (): void {
    $this->getJson('/clients/auth/two-factor', bearer(issuePair(Client::factory()->create(), 'clients')))->assertNotFound();
});
