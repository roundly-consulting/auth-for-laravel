<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Contracts\AssessesLoginRisk;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\LoginRiskContext;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;
use RoundlyConsulting\Auth\Enums\RiskLevel;
use RoundlyConsulting\Auth\Events\LoginActivityRecorded;
use RoundlyConsulting\Auth\Events\NewDeviceDetected;
use RoundlyConsulting\Auth\Events\SuspiciousLoginDetected;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\LoginDenied;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Notifications\NewDeviceLoginNotification;
use RoundlyConsulting\Auth\Notifications\SignInBlockedNotification;
use RoundlyConsulting\Auth\Notifications\SuspiciousSessionNotification;
use RoundlyConsulting\Auth\Notifications\UnusualSignInNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

final class FixedRiskAssessor implements AssessesLoginRisk
{
    public static RiskLevel $level = RiskLevel::Low;

    public function assess(LoginRiskContext $context): RiskAssessment
    {
        return new RiskAssessment(self::$level, ['test']);
    }
}

function login(User $user, string $userAgent = 'PestBrowser/1.0', ?string $device = null): LoginResult
{
    return Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext($userAgent, deviceId: $device));
}

it('does not treat the very first login as a new device, but a second device is', function (): void {
    Event::fake([NewDeviceDetected::class]);
    Notification::fake();
    $user = User::factory()->create();

    login($user, 'Laptop');
    login($user, 'Laptop');
    Event::assertNotDispatched(NewDeviceDetected::class);

    login($user, 'Phone');
    Event::assertDispatched(NewDeviceDetected::class);
    Notification::assertSentTo($user, NewDeviceLoginNotification::class);

    expect(LoginActivity::query()->where('is_new_device', true)->count())->toBe(1);
});

it('does not let an unauthenticated request make an attacker device known', function (string $request): void {
    Event::fake([NewDeviceDetected::class]);
    Notification::fake();
    $user = User::factory()->create(['email' => 'victim@example.com']);
    login($user, 'Laptop', 'owner-laptop');

    // Anyone who knows the address can make the package record a "succeeded" request…
    $this->postJson('/users/auth/'.$request, ['email' => 'victim@example.com'], ['X-Device-Id' => 'attacker-box', 'User-Agent' => 'EvilBrowser/1.0'])->assertStatus(202);

    // …which must not make the next sign-in from that device (with a stolen password) a known one.
    login($user, 'EvilBrowser/1.0', 'attacker-box');

    Event::assertDispatched(NewDeviceDetected::class);
    Notification::assertSentTo($user, NewDeviceLoginNotification::class);
})->with(['password/forgot', 'login/magic-link', 'login/otp']);

it('does not let a re-authentication make its device known', function (): void {
    Event::fake([NewDeviceDetected::class]);
    Notification::fake();
    $user = User::factory()->create();
    login($user, 'Laptop', 'owner-laptop');
    $pair = issuePair($user);

    // A stolen access token re-authenticates from another device…
    $this->postJson('/users/auth/reauthenticate', ['method' => 'password', 'password' => 'correct-horse-battery'], ['Authorization' => 'Bearer '.$pair->accessToken, 'X-Device-Id' => 'attacker-box', 'User-Agent' => 'EvilBrowser/1.0'])
        ->assertOk();

    // …which must not make the first real sign-in from that device a known one.
    login($user, 'EvilBrowser/1.0', 'attacker-box');

    Event::assertDispatched(NewDeviceDetected::class);
    Notification::assertSentTo($user, NewDeviceLoginNotification::class);
});

it('prefers the device header over the user agent', function (): void {
    Event::fake([NewDeviceDetected::class]);
    $user = User::factory()->create();

    login($user, 'UA/1', 'device-a');
    login($user, 'UA/2', 'device-a');
    Event::assertNotDispatched(NewDeviceDetected::class);
});

it('flags a first login when skip_first_login is off, and nothing when detection is off', function (): void {
    Event::fake([NewDeviceDetected::class]);
    $this->configureGuard('users', ['activity.new_device.skip_first_login' => false]);
    login(User::factory()->create());
    Event::assertDispatchedTimes(NewDeviceDetected::class, 1);

    $this->configureGuard('users', ['activity.new_device.enabled' => false]);
    login(User::factory()->create(), 'Other');
    Event::assertDispatchedTimes(NewDeviceDetected::class, 1);
});

it('lists the account\'s own activity over http, paginated', function (): void {
    $user = User::factory()->create();
    login($user);
    login($user);

    $this->getJson('/users/auth/activity?per_page=1', bearer(issuePair($user)))
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.outcome', 'succeeded')
        ->assertJsonPath('meta.total', 2)
        ->assertJsonMissingPath('data.0.identifier');
});

it('dispatches the enrichment hook with ids only, and lets hosts enrich rows', function (): void {
    Event::fake([LoginActivityRecorded::class]);
    login(User::factory()->create());

    $row = LoginActivity::query()->sole();
    $row->enrich('sk', 'Bratislava');

    expect($row->country_code)->toBe('SK')->and($row->city)->toBe('Bratislava');
    Event::assertDispatched(LoginActivityRecorded::class, fn (LoginActivityRecorded $event): bool => $event->activityId === $row->getKey());
});

it('applies the configured risk reactions', function (RiskLevel $level, string $reaction, string $outcome): void {
    Event::fake([SuspiciousLoginDetected::class]);
    Notification::fake();
    $this->configureGuard('users', ['risk.assessor' => FixedRiskAssessor::class, 'risk.reactions.high' => $reaction, 'risk.reactions.elevated' => $reaction]);
    FixedRiskAssessor::$level = $level;
    $user = User::factory()->create();

    if ($outcome === 'denied') {
        expect(fn () => login($user))->toThrow(InvalidCredentials::class);
        Notification::assertSentTo($user, SignInBlockedNotification::class);
        Notification::assertNotSentTo($user, SuspiciousSessionNotification::class);
        Event::assertDispatched(SuspiciousLoginDetected::class);
    } elseif ($outcome === 'notified') {
        expect(login($user)->isAuthenticated())->toBeTrue();
        Notification::assertSentTo($user, UnusualSignInNotification::class);
        Notification::assertNotSentTo($user, SuspiciousSessionNotification::class);
    } else {
        expect(login($user)->isAuthenticated())->toBeTrue();
        Notification::assertNothingSentTo($user);
    }

    FixedRiskAssessor::$level = RiskLevel::Low;
})->with([
    'high → deny' => [RiskLevel::High, 'deny', 'denied'],
    'elevated → notify' => [RiskLevel::Elevated, 'notify', 'notified'],
    'high → allow' => [RiskLevel::High, 'allow', 'allowed'],
]);

it('keeps the risk alerts apart from the refresh-token-reuse mail a host swapped or disabled', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['risk.assessor' => FixedRiskAssessor::class, 'risk.reactions.high' => 'deny', 'risk.reactions.elevated' => 'notify', 'notifications.classes.refresh_token_reuse' => null]);
    $user = User::factory()->create();

    FixedRiskAssessor::$level = RiskLevel::High;
    expect(fn () => login($user))->toThrow(InvalidCredentials::class);

    FixedRiskAssessor::$level = RiskLevel::Elevated;
    expect(login($user)->isAuthenticated())->toBeTrue();

    Notification::assertSentToTimes($user, SignInBlockedNotification::class, 1);
    Notification::assertSentToTimes($user, UnusualSignInNotification::class, 1);
    FixedRiskAssessor::$level = RiskLevel::Low;
});

it('steps up to a second factor on high risk, or denies when there is none', function (): void {
    $this->configureGuard('users', ['risk.assessor' => FixedRiskAssessor::class]);
    FixedRiskAssessor::$level = RiskLevel::High;

    $enrolled = User::factory()->create();
    enableTotp($enrolled);
    expect(login($enrolled)->requiresChallenge())->toBeTrue();

    expect(fn () => login(User::factory()->create()))->toThrow(InvalidCredentials::class)
        ->and(LoginActivity::query()->where('reason', 'step_up_unavailable')->count())->toBe(1);

    $this->configureGuard('users', ['risk.deny_response' => 'explicit']);
    expect(fn () => login(User::factory()->create()))->toThrow(LoginDenied::class);

    FixedRiskAssessor::$level = RiskLevel::Low;
});

it('steps up a magic-link login on high risk even when email logins skip 2FA', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['risk.assessor' => FixedRiskAssessor::class, 'two_factor.after_email_login' => false]);
    FixedRiskAssessor::$level = RiskLevel::High;
    $magicLink = static function (User $user): LoginResult {
        Authentication::guard('users')->requestMagicLink($user->email, sessionContext());

        return Authentication::guard('users')->consumeMagicLink(tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url), sessionContext());
    };

    $enrolled = User::factory()->create();
    enableTotp($enrolled);

    expect($magicLink($enrolled)->requiresChallenge())->toBeTrue()
        ->and(fn () => $magicLink(User::factory()->create()))->toThrow(InvalidCredentials::class)
        ->and(LoginActivity::query()->where('reason', 'step_up_unavailable')->count())->toBe(1);

    FixedRiskAssessor::$level = RiskLevel::Low;
});
