<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
use Symfony\Component\HttpFoundation\Response;

beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['tokens.access_ttl' => 7200]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

/**
 * @return list<string>
 */
function requiredForWithout(SensitiveAction ...$without): array
{
    return array_values(array_map(
        static fn (SensitiveAction $action): string => $action->value,
        array_filter(SensitiveAction::cases(), static fn (SensitiveAction $action): bool => ! in_array($action, $without, true)),
    ));
}

/**
 * Runs the endpoint(s) a sensitive action gates from a session that is past the
 * re-authentication window; returns each response with the status it answers when
 * the action is allowed.
 *
 * @return list<array{TestResponse<Response>, int}>
 */
function performSensitiveAction(SensitiveAction $action): array
{
    $user = $action === SensitiveAction::SetPassword ? User::factory()->passwordless()->create() : User::factory()->create();

    if (in_array($action, [SensitiveAction::DisableTwoFactor, SensitiveAction::RegenerateRecoveryCodes], true)) {
        enableTotp($user);
    }

    $passkey = $action === SensitiveAction::RemovePasskey ? addPasskey($user) : null;
    $headers = bearer(issuePair($user));
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');
    $test = test();

    return match ($action) {
        SensitiveAction::EnableTwoFactor => [[$test->postJson('/users/auth/two-factor', [], $headers), 200]],
        SensitiveAction::DisableTwoFactor => [[$test->deleteJson('/users/auth/two-factor', [], $headers), 200]],
        SensitiveAction::RegenerateRecoveryCodes => [[$test->postJson('/users/auth/two-factor/recovery-codes', [], $headers), 200]],
        SensitiveAction::RegisterPasskey => [
            [$test->postJson('/users/auth/passkeys/options', [], $headers), 200],
            [$test->postJson('/users/auth/passkeys', ['credential' => attestationPayload(VirtualAuthenticator::es256()->register(Passkeys::for($user)->registrationOptions()))], $headers), 201],
        ],
        SensitiveAction::RemovePasskey => [[$test->deleteJson('/users/auth/passkeys/'.$passkey?->getKey(), [], $headers), 200]],
        SensitiveAction::ChangeEmail => [[$test->postJson('/users/auth/email/change', ['email' => 'new@example.com'], $headers), 202]],
        SensitiveAction::SetPassword => [[$test->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], $headers), 200]],
        SensitiveAction::LogoutEverywhere => [[$test->postJson('/users/auth/logout/everywhere', [], $headers), 200]],
    };
}

dataset('sensitive actions', array_combine(
    array_map(static fn (SensitiveAction $action): string => $action->value, SensitiveAction::cases()),
    array_map(static fn (SensitiveAction $action): array => [$action], SensitiveAction::cases()),
));

it('requires a recent authentication for every listed action', function (SensitiveAction $action): void {
    $responses = performSensitiveAction($action);

    expect($responses)->not->toBeEmpty();

    foreach ($responses as [$response]) {
        $response->assertForbidden()->assertJsonPath('code', 'reauthentication_required');
    }
})->with('sensitive actions');

it('drops the requirement for an action removed from the guard list', function (SensitiveAction $action): void {
    $this->configureGuard('users', ['reauthentication.required_for' => requiredForWithout($action)]);

    $responses = performSensitiveAction($action);

    expect($responses)->not->toBeEmpty();

    foreach ($responses as [$response, $status]) {
        $response->assertStatus($status);
    }
})->with('sensitive actions');

it('drops the requirement for an action removed from the global defaults', function (SensitiveAction $action): void {
    config()->set('authentication.defaults.reauthentication.required_for', requiredForWithout($action));
    app(GuardRegistry::class)->flush();

    foreach (performSensitiveAction($action) as [$response, $status]) {
        $response->assertStatus($status);
    }
})->with('sensitive actions');

it('keeps the email-change switch as an opt-out of its own gate', function (): void {
    $this->configureGuard('users', ['email_change.require_reauthentication' => false]);

    [[$response, $status]] = performSensitiveAction(SensitiveAction::ChangeEmail);

    $response->assertStatus($status);
});

it('makes a passwordless account with a second factor re-prove it before setting a password', function (): void {
    $user = User::factory()->passwordless()->create();
    $secret = enableTotp($user);
    $pair = issuePair($user);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    $this->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('code', 'reauthentication_required')
        ->assertJsonPath('methods', ['totp', 'recovery_code']);

    $this->postJson('/users/auth/reauthenticate/otp', [], bearer($pair))->assertStatus(422)->assertJsonPath('code', 'factor_not_allowed');
    $this->postJson('/users/auth/reauthenticate', ['method' => 'email_otp', 'code' => '000000'], bearer($pair))->assertStatus(422)->assertJsonPath('code', 'factor_not_allowed');

    $this->postJson('/users/auth/reauthenticate', ['method' => 'totp', 'code' => totpCode($secret)], bearer($pair))->assertOk();
    $this->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], bearer($pair))->assertOk();

    expect($user->fresh()?->hasPassword())->toBeTrue();
});

it('lets a passwordless account without a second factor set a password after an email code', function (): void {
    $user = User::factory()->passwordless()->create();
    $pair = issuePair($user);
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    $this->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], bearer($pair))
        ->assertForbidden()
        ->assertJsonPath('methods', ['email_otp']);

    $this->postJson('/users/auth/reauthenticate/otp', [], bearer($pair))->assertStatus(202);
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;

    $this->postJson('/users/auth/reauthenticate', ['method' => 'email_otp', 'code' => $code], bearer($pair))->assertOk();
    $this->putJson('/users/auth/password', ['password' => 'a-brand-new-passphrase'], bearer($pair))->assertOk();
});
