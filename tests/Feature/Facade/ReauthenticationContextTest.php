<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Exceptions\FactorNotAllowed;
use RoundlyConsulting\Auth\Exceptions\ReauthenticationRequired;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['tokens.access_ttl' => 7200]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('gates a sensitive action until the session re-proves itself', function (): void {
    $user = User::factory()->create();
    $current = currentTokenOf(issuePair($user));
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');
    $reauthentication = Authentication::guard('users')->reauthentication();

    expect($reauthentication->methods($user))->toBe([ReauthenticationMethod::Password])
        ->and(fn () => $reauthentication->ensureFor(SensitiveAction::DisableTwoFactor, $user, $current))->toThrow(ReauthenticationRequired::class)
        ->and(fn () => $reauthentication->ensureRecent($user, $current))->toThrow(ReauthenticationRequired::class);

    $until = $reauthentication->confirm($user, new ReauthenticationData(ReauthenticationMethod::Password, $current, sessionContext(), password: 'correct-horse-battery'));

    expect($until->toIso8601ZuluString())->toBe('2026-09-26T10:45:00Z');
    $reauthentication->ensureFor(SensitiveAction::DisableTwoFactor, $user, $current);
    $reauthentication->ensureRecent($user, $current);
    expect(fn () => $reauthentication->ensureRecent($user, $current, seconds: 1))->not->toThrow(ReauthenticationRequired::class);
});

it('lets an action the guard does not gate through', function (): void {
    $this->configureGuard('users', ['reauthentication.required_for' => ['disable_two_factor']]);
    $user = User::factory()->create();
    $current = currentTokenOf(issuePair($user));
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    Authentication::reauthentication()->ensureFor(SensitiveAction::LogoutEverywhere, $user, $current);

    expect(fn () => Authentication::reauthentication()->ensureFor(SensitiveAction::DisableTwoFactor, $user, $current))->toThrow(ReauthenticationRequired::class);
});

it('gates an email change only while email_change.require_reauthentication is on', function (): void {
    $user = User::factory()->create();
    $current = currentTokenOf(issuePair($user));
    CarbonImmutable::setTestNow('2026-09-26 10:30:00');

    expect(fn () => Authentication::reauthentication()->ensureFor(SensitiveAction::ChangeEmail, $user, $current))->toThrow(ReauthenticationRequired::class);

    $this->configureGuard('users', ['email_change.require_reauthentication' => false]);

    Authentication::reauthentication()->ensureFor(SensitiveAction::ChangeEmail, $user, $current);
    expect(Authentication::config()->requiresReauthentication(SensitiveAction::ChangeEmail))->toBeFalse();
});

it('mails a code to a passwordless account and offers a passkey ceremony to one with a passkey', function (): void {
    $passwordless = User::factory()->passwordless()->create();

    Authentication::reauthentication()->sendCode($passwordless, sessionContext());
    Notification::assertSentTo($passwordless, EmailOtpNotification::class);

    $withPasskey = User::factory()->create();
    registerVirtualPasskey($withPasskey);
    $options = Authentication::reauthentication()->passkeyOptions($withPasskey, currentTokenOf(issuePair($withPasskey)));

    expect($options->ceremonyId)->not->toBe('')
        ->and(Authentication::reauthentication()->methods($withPasskey))->toBe([ReauthenticationMethod::Passkey])
        ->and(fn () => Authentication::reauthentication()->sendCode($withPasskey, sessionContext()))->toThrow(FactorNotAllowed::class);
});
