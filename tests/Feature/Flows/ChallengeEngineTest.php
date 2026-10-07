<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Auth\Actions\Challenges\AdvanceChallenge;
use RoundlyConsulting\Auth\Actions\Challenges\FinalizeChallenge;
use RoundlyConsulting\Auth\Actions\Challenges\FindActiveChallenge;
use RoundlyConsulting\Auth\Actions\Challenges\RecordChallengeFailure;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Events\ChallengeFailed;
use RoundlyConsulting\Auth\Events\ChallengeStepCompleted;
use RoundlyConsulting\Auth\Events\LoginChallenged;
use RoundlyConsulting\Auth\Exceptions\AccountDisabled;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Exceptions\FactorNotAllowed;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

function challengeFor(User $user, ?SessionContext $context = null): PendingChallenge
{
    $result = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), $context ?? sessionContext());

    expect($result->requiresChallenge())->toBeTrue();

    return $result->challenge;
}

function passStep(PendingChallenge $pending, ?SessionContext $context = null): LoginResult
{
    $context ??= sessionContext();
    $challenge = app(FindActiveChallenge::class)->execute('users', $pending->token, $context);

    return app(AdvanceChallenge::class)->execute($challenge, ChallengeStep::SecondFactor, $pending->token, FactorMethod::Totp, [AuthMethodReference::Otp], $context);
}

beforeEach(function (): void {
    $this->user = User::factory()->create();
    enableTotp($this->user);
});

it('starts a challenge for an enrolled second factor, over http too', function (): void {
    Event::fake([LoginChallenged::class]);

    $this->postJson('/users/auth/login', ['identifier' => $this->user->email, 'password' => 'correct-horse-battery'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'challenge')
        ->assertJsonPath('method', 'password')
        ->assertJsonPath('attempts_left', 5)
        ->assertJsonPath('completed', [])
        ->assertJsonPath('remaining.0.step', 'second_factor')
        ->assertJsonPath('remaining.0.methods', ['totp', 'recovery_code']);

    $challenge = LoginChallenge::query()->sole();

    expect($challenge->token_hash)->toHaveLength(64)
        ->and($challenge->contextValue('amr'))->toBe(['pwd'])
        ->and(LoginActivity::query()->where('outcome', 'challenged')->sole()->challenge_id)->toBe($challenge->getKey());
    Event::assertDispatched(LoginChallenged::class);
});

it('completes the login once every step passed, claiming mfa', function (): void {
    Event::fake([ChallengeStepCompleted::class]);

    $result = passStep(challengeFor($this->user));
    $claims = claimsOf($result->tokens);

    expect($result->isAuthenticated())->toBeTrue()
        ->and($claims->authMethods())->toBe(['pwd', 'otp', 'mfa'])
        ->and(LoginChallenge::query()->sole()->completed_at)->not->toBeNull();
    Event::assertDispatched(ChallengeStepCompleted::class, fn (ChallengeStepCompleted $event): bool => $event->step === ChallengeStep::SecondFactor);
});

it('expires exactly at its expiry', function (): void {
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
    $pending = challengeFor($this->user);

    CarbonImmutable::setTestNow('2026-09-26 10:04:59');
    expect(app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext()))->toBeInstanceOf(LoginChallenge::class);

    CarbonImmutable::setTestNow('2026-09-26 10:05:00');
    expect(fn () => app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext()))->toThrow(ChallengeInvalid::class);
    CarbonImmutable::setTestNow();
});

it('dies after the maximum number of failed attempts', function (): void {
    Event::fake([ChallengeFailed::class]);
    $pending = challengeFor($this->user);
    $challenge = LoginChallenge::query()->sole();

    foreach ([4, 3, 2, 1, 0] as $left) {
        expect(app(RecordChallengeFailure::class)->execute($challenge, ActivityOutcome::FailedFactor, sessionContext()))->toBe($left);
    }

    expect(app(RecordChallengeFailure::class)->execute($challenge, ActivityOutcome::FailedFactor, sessionContext()))->toBe(0)
        ->and($challenge->fresh()?->invalidated_reason)->toBe('attempts_exhausted')
        ->and(fn () => passStep($pending))->toThrow(ChallengeInvalid::class);
    Event::assertDispatchedTimes(ChallengeFailed::class, 6);
});

it('lets exactly one of two concurrent step submissions advance', function (): void {
    $pending = challengeFor($this->user);
    $stale = app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext());

    passStep($pending);

    expect(fn () => app(AdvanceChallenge::class)->execute($stale, ChallengeStep::SecondFactor, $pending->token, FactorMethod::Totp, [], sessionContext()))->toThrow(ChallengeInvalid::class);
});

it('refuses to advance past a step other than the one the caller verified', function (): void {
    $pending = challengeFor($this->user);
    $challenge = app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext());

    expect(fn () => app(AdvanceChallenge::class)->execute($challenge, ChallengeStep::Passkey, $pending->token, FactorMethod::Passkey, [], sessionContext()))->toThrow(ChallengeInvalid::class)
        ->and(LoginChallenge::query()->sole())
        ->version->toBe(0)
        ->completed()->toBe([]);
});

it('refuses a replayed final step', function (): void {
    $pending = challengeFor($this->user);
    $challenge = app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext());
    $advanced = passStep($pending);

    expect($advanced->isAuthenticated())->toBeTrue()
        ->and(fn () => app(FinalizeChallenge::class)->execute($challenge->fresh(), sessionContext()))->toThrow(ChallengeInvalid::class)
        ->and(LoginActivity::query()->where('outcome', 'replayed')->count())->toBe(1);
});

it('dies when the account is invalidated before the challenge finalizes', function (): void {
    $pending = challengeFor($this->user);

    $this->user->forceFill(['token_version' => 7])->save();

    expect(fn () => passStep($pending))->toThrow(ChallengeInvalid::class)
        ->and(LoginChallenge::query()->sole()->invalidated_reason)->toBe('superseded');
});

it('re-checks the account state at finalize', function (): void {
    $pending = challengeFor($this->user);
    $this->user->forceFill(['disabled_at' => now()])->save();

    passStep($pending);
})->throws(AccountDisabled::class);

it('supersedes the oldest challenges beyond the active cap', function (): void {
    $first = challengeFor($this->user);
    challengeFor($this->user);
    challengeFor($this->user);
    challengeFor($this->user);

    expect(LoginChallenge::query()->whereNull('invalidated_at')->count())->toBe(3)
        ->and(fn () => app(FindActiveChallenge::class)->execute('users', $first->token, sessionContext()))->toThrow(ChallengeInvalid::class);
});

it('binds the challenge to the user agent and device, not the ip', function (): void {
    $pending = challengeFor($this->user, sessionContext('PhoneBrowser', '1.1.1.1', 'device-1'));

    expect(app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext('PhoneBrowser', '2.2.2.2', 'device-1')))->toBeInstanceOf(LoginChallenge::class)
        ->and(fn () => app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext('OtherBrowser', '1.1.1.1', 'device-1')))->toThrow(ChallengeInvalid::class)
        ->and(fn () => app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext('PhoneBrowser', '1.1.1.1', 'device-2')))->toThrow(ChallengeInvalid::class)
        ->and(LoginChallenge::query()->sole()->attempts)->toBe(2)
        ->and(LoginActivity::query()->where('outcome', 'fingerprint_mismatch')->count())->toBe(2);
});

it('binds to the ip when configured and to nothing when every binding is off', function (): void {
    $this->configureGuard('users', ['challenge.bind.ip' => true]);
    $pending = challengeFor($this->user, sessionContext('UA', '1.1.1.1'));
    expect(fn () => app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext('UA', '2.2.2.2')))->toThrow(ChallengeInvalid::class);

    $this->configureGuard('users', ['challenge.bind' => ['user_agent' => false, 'ip' => false, 'device_header' => false]]);
    $pending = challengeFor($this->user, sessionContext('UA', '1.1.1.1'));
    expect(app(FindActiveChallenge::class)->execute('users', $pending->token, sessionContext('Other', '9.9.9.9')))->toBeInstanceOf(LoginChallenge::class);
});

it('rejects a challenge token of another guard', function (): void {
    $pending = challengeFor($this->user);

    app(FindActiveChallenge::class)->execute('clients', $pending->token, sessionContext());
})->throws(ChallengeInvalid::class);

it('only accepts the next step with one of its methods', function (): void {
    challengeFor($this->user);
    $challenge = LoginChallenge::query()->sole();

    expect($challenge->nextRequirement([ChallengeStep::SecondFactor], FactorMethod::RecoveryCode)->step)->toBe(ChallengeStep::SecondFactor)
        ->and(fn () => $challenge->nextRequirement([ChallengeStep::SecondFactor], FactorMethod::Passkey))->toThrow(FactorNotAllowed::class)
        ->and(fn () => $challenge->nextRequirement([ChallengeStep::EnrolTwoFactor], FactorMethod::TotpEnrolment))->toThrow(FactorNotAllowed::class);
});

it('uses the longer ttl when an enrolment step is pending', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $user = User::factory()->create();
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');

    $pending = challengeFor($user);

    expect($pending->expiresAt->toDateTimeString())->toBe('2026-09-26 10:15:00');
    CarbonImmutable::setTestNow();
});

it('refuses forced enrolment for an unverified email, or when enrolment is off', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $user = User::factory()->unverified()->create();

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'])
        ->assertForbidden()
        ->assertJsonPath('code', 'enrolment_required');

    $this->configureGuard('users', ['challenge.allow_enrolment' => false]);
    $verified = User::factory()->create();

    expect(fn () => challengeFor($verified))->toThrow(EnrolmentRequired::class);
});
