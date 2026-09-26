<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Events\TwoFactorEnabled;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Every factor step and management endpoint re-checks the account's CURRENT factor state:
 * a challenge or request that was valid when it started must not act on a factor that
 * changed meanwhile.
 */
function openChallenge(User $user, string $userAgent = 'PestBrowser/1.0'): string
{
    return test()->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => $userAgent])
        ->assertOk()
        ->assertJsonPath('status', 'challenge')
        ->json('challenge_token');
}

beforeEach(function (): void {
    Notification::fake();
});

it('refuses a forced totp enrolment once the owner enrolled elsewhere, and ends that challenge', function (): void {
    Event::fake([TwoFactorEnabled::class]);
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'invalidation.two_factor_changed' => 'none']);
    $user = User::factory()->create();

    // An attacker holding the password opens a challenge that needs enrol_two_factor…
    $attacker = openChallenge($user, 'Attacker/1.0');

    // …then the owner enrols their authenticator in their own challenge.
    $owner = openChallenge($user);
    $setup = $this->postJson('/users/auth/challenge/two-factor/enrol', ['challenge_token' => $owner], ['User-Agent' => 'PestBrowser/1.0'])->assertOk()->json();
    $this->postJson('/users/auth/challenge/two-factor/enrol/confirm', ['challenge_token' => $owner, 'code' => totpCode($setup['secret'])], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    $this->postJson('/users/auth/challenge/two-factor/enrol/confirm', ['challenge_token' => $attacker, 'code' => '000000'], ['User-Agent' => 'Attacker/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'challenge_invalid');

    $stale = Models::challenges()->whereNull('completed_at')->sole();

    expect($stale->invalidated_at)->not->toBeNull()
        ->and($stale->invalidated_reason)->toBe('factor_changed');
    Event::assertDispatchedTimes(TwoFactorEnabled::class, 1);
});

it('refuses a forced totp enrolment once totp was enabled out of band, whatever the code', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $user = User::factory()->create();
    $token = openChallenge($user);

    $secret = enableTotp($user);

    $this->postJson('/users/auth/challenge/two-factor/enrol/confirm', ['challenge_token' => $token, 'code' => totpCode($secret)], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'challenge_invalid');

    expect(Models::challenges()->sole()->invalidated_at)->not->toBeNull();
    Notification::assertNothingSent();
});

it('re-checks the enrolment gate when the enrolment is confirmed', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'challenge.enrolment_requires_verified_email' => false]);
    $user = User::factory()->unverified()->create();
    $token = openChallenge($user);
    $setup = $this->postJson('/users/auth/challenge/two-factor/enrol', ['challenge_token' => $token], ['User-Agent' => 'PestBrowser/1.0'])->assertOk()->json();

    $this->configureGuard('users', ['challenge.enrolment_requires_verified_email' => true]);

    $this->postJson('/users/auth/challenge/two-factor/enrol/confirm', ['challenge_token' => $token, 'code' => totpCode($setup['secret'])], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(403)
        ->assertJsonPath('code', 'enrolment_required');

    expect($user->fresh()?->hasTwoFactorEnabled())->toBeFalse();
});
