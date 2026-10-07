<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Hashing\HashManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\Account\Reauthenticate;
use RoundlyConsulting\Auth\Actions\Passwords\ChangePassword;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\LoginThrottled;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Notifications\AccountExistsNotification;
use RoundlyConsulting\Auth\Notifications\VerifyEmailNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\CountingHasher;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\Fixtures\ReentrantHasher;
use RoundlyConsulting\Auth\Tests\Fixtures\ReentrantRateLimiter;
use RoundlyConsulting\Auth\Tests\Fixtures\Support\HighRiskAssessor;

function failLogin(string $identifier, string $ip = '10.0.0.1'): void
{
    try {
        Authentication::guard('users')->attempt(new PasswordCredentials($identifier, 'wrong-password'), sessionContext(ip: $ip));
    } catch (InvalidCredentials) {
        // counted
    }
}

it('throttles identifier+ip after five failures, with Retry-After, before any hashing', function (): void {
    Event::fake([LoginThrottled::class]);
    $user = User::factory()->create();

    foreach (range(1, 5) as $attempt) {
        failLogin($user->email);
    }

    $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'], ['REMOTE_ADDR' => '10.0.0.1'])
        ->assertStatus(429)
        ->assertHeader('Retry-After')
        ->assertJsonPath('code', 'too_many_attempts');

    expect(LoginActivity::query()->where('outcome', 'throttled')->count())->toBe(1);
    Event::assertDispatched(LoginThrottled::class, fn (LoginThrottled $event): bool => $event->kind === ThrottleKind::Login && $event->retryAfter > 0);
});

it('does not throttle the same identifier from another ip', function (): void {
    $user = User::factory()->create();

    foreach (range(1, 5) as $attempt) {
        failLogin($user->email, '10.0.0.1');
    }

    expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext(ip: '10.0.0.2'))->isAuthenticated())->toBeTrue();
});

it('caps an identifier across ips and an ip across identifiers', function (): void {
    $this->configureGuard('users', ['throttle.login_account.max' => 3, 'throttle.login_ip.max' => 4]);
    $user = User::factory()->create();

    foreach (['1.1.1.1', '1.1.1.2', '1.1.1.3'] as $ip) {
        failLogin($user->email, $ip);
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext(ip: '1.1.1.9')))->toThrow(TooManyAttempts::class);

    foreach (['a@x.test', 'b@x.test', 'c@x.test', 'd@x.test'] as $identifier) {
        failLogin($identifier, '9.9.9.9');
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials('e@x.test', 'x'), sessionContext(ip: '9.9.9.9')))->toThrow(TooManyAttempts::class);
});

it('clears the identifier+ip bucket on success but not the volumetric ones', function (): void {
    $this->configureGuard('users', ['throttle.login_ip.max' => 6]);
    $user = User::factory()->create();

    foreach (range(1, 4) as $attempt) {
        failLogin($user->email);
    }

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    foreach (range(1, 2) as $attempt) {
        failLogin($user->email);
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))->toThrow(TooManyAttempts::class);
});

it('never counts a success toward the limit', function (): void {
    $user = User::factory()->create();

    foreach (range(1, 8) as $attempt) {
        expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->isAuthenticated())->toBeTrue();
    }
});

/**
 * @param  Closure(int): void  $guess
 */
function concurrentGuesses(Closure $guess, int $burst = 20): ReentrantHasher
{
    $hasher = new ReentrantHasher(app(HashManager::class)->driver('bcrypt'), $guess, $burst);
    Hash::swap($hasher);

    return $hasher;
}

it('counts concurrent password guesses before any of them is hashed', function (): void {
    $this->configureGuard('users', ['throttle.login.max' => 5, 'throttle.login_account.max' => 5, 'throttle.login_ip.max' => 5]);
    $user = User::factory()->create();

    $guess = static function (int $n) use ($user): void {
        try {
            Authentication::guard('users')->attempt(new PasswordCredentials($user->email, "guess-{$n}"), sessionContext());
        } catch (AuthException) {
            // wrong, or throttled
        }
    };
    $hasher = concurrentGuesses($guess);

    $guess(0);

    expect($hasher->checks)->toBe(5);
});

it('counts concurrent re-authentication and current-password guesses before hashing', function (string $action): void {
    $user = User::factory()->create();
    $current = CurrentToken::fromClaims(claimsOf(issuePair($user)));

    $guess = static function (int $n) use ($action, $user, $current): void {
        try {
            match ($action) {
                'reauthenticate' => app(Reauthenticate::class)->execute('users', $user, new ReauthenticationData(ReauthenticationMethod::Password, $current, sessionContext(), password: "guess-{$n}")),
                'change password' => app(ChangePassword::class)->execute('users', $user, new ChangePasswordData("guess-{$n}", 'a-brand-new-passphrase', $current, sessionContext())),
            };
        } catch (AuthException|ValidationException) {
            // wrong, or throttled
        }
    };
    $hasher = concurrentGuesses($guess);

    $guess(0);

    // reauthentication.max = 5 per session.
    expect($hasher->checks)->toBe(5);
})->with(['reauthenticate', 'change password']);

it('keeps a throttled request out of the counts', function (): void {
    $this->configureGuard('users', ['throttle.login.max' => 2, 'throttle.login_account.max' => 3]);
    $user = User::factory()->create();

    failLogin($user->email, '1.1.1.1');
    failLogin($user->email, '1.1.1.1');

    // The identifier+ip bucket is full: refused without counting in the account bucket.
    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'wrong-password'), sessionContext(ip: '1.1.1.1')))->toThrow(TooManyAttempts::class);

    // So the account bucket (3) still has one attempt left from another ip.
    expect(Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext(ip: '2.2.2.2'))->isAuthenticated())->toBeTrue();
});

it('counts the composed and decomposed spellings of an identifier in one bucket', function (): void {
    $user = User::factory()->create(['email' => "jos\u{00E9}@example.com"]);

    foreach (range(1, 5) as $attempt) {
        failLogin("jose\u{0301}@example.com");
    }

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))->toThrow(TooManyAttempts::class);
});

it('lets exactly one of two concurrent requests through a per-account cooldown', function (string $flow): void {
    Notification::fake();
    $this->configureGuard('users', ['registration.login_after' => false]);
    $user = User::factory()->unverified()->create();

    [$key, $request] = match ($flow) {
        'signed-in verification' => ['verification-resend', static fn () => Authentication::guard('users')->email()->requestVerification($user, sessionContext())],
        'guest verification resend' => ['verification-resend', static fn () => Authentication::guard('users')->email()->resendVerification((string) $user->email, sessionContext())],
        'registration of a taken address' => ['account-exists', static fn () => Authentication::guard('users')->register(new RegistrationData((string) $user->email, 'a-long-enough-passphrase', sessionContext()))],
    };

    // The second request checks the cooldown just as the first one did, before either starts it.
    app()->instance(RateLimiter::class, new ReentrantRateLimiter(app('cache')->store(), $key, $request));
    $request();

    $flow === 'registration of a taken address'
        ? Notification::assertSentOnDemandTimes(AccountExistsNotification::class, 1)
        : Notification::assertSentToTimes($user, VerifyEmailNotification::class, 1);
})->with(['signed-in verification', 'guest verification resend', 'registration of a taken address']);

it('counts guesses against a locked account like any other, so a lock is no way around the limit', function (): void {
    $user = User::factory()->create(['locked_until' => now()->addHour()]);
    $hasher = new CountingHasher(app(HashManager::class)->driver('bcrypt'));
    Hash::swap($hasher);

    foreach (range(1, 20) as $attempt) {
        try {
            Authentication::guard('users')->attempt(new PasswordCredentials($user->email, "guess-{$attempt}"), sessionContext());
        } catch (AuthException) {
            // wrong-looking, or throttled
        }
    }

    // `login` allows 5 per identifier+IP: the rest are refused before any hashing.
    expect($hasher->checked)->toHaveCount(5)
        ->and(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext()))->toThrow(TooManyAttempts::class);
});

function tryPassword(User $user, string $password): void
{
    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, $password), sessionContext());
}

it('keeps the attempt of a correct password the login refuses uniformly', function (array $config, array $state): void {
    Notification::fake();
    $this->configureGuard('users', [...$config, 'throttle.login.max' => 5]);
    $user = User::factory()->create($state);

    // The correct password is one of five candidates: its refusal must count like the others.
    foreach (['guess-1', 'guess-2', 'correct-horse-battery', 'guess-3', 'guess-4'] as $candidate) {
        expect(fn () => tryPassword($user, $candidate))->toThrow(InvalidCredentials::class);
    }

    expect(fn () => tryPassword($user, 'guess-5'))->toThrow(TooManyAttempts::class);
})->with([
    'disabled' => [['login.reveal_account_state' => false], ['disabled_at' => now()]],
    'unverified' => [['login.reveal_account_state' => false, 'verification.mode' => 'required_for_login'], ['email_verified_at' => null]],
    'risk deny' => [['risk.assessor' => HighRiskAssessor::class, 'risk.reactions.high' => 'deny'], []],
    'step-up unavailable' => [['risk.assessor' => HighRiskAssessor::class, 'risk.reactions.high' => 'require_second_factor'], []],
]);

it('leaves the lockout counter alone when a correct password is refused uniformly', function (string $reaction): void {
    Notification::fake();
    $this->configureGuard('users', ['lockout.enabled' => true, 'risk.assessor' => HighRiskAssessor::class, 'risk.reactions.high' => $reaction]);
    $user = User::factory()->create(['failed_login_count' => 3]);

    expect(fn () => tryPassword($user, 'correct-horse-battery'))->toThrow(InvalidCredentials::class)
        ->and($user->fresh()?->getAttribute('failed_login_count'))->toBe(3);
})->with(['deny', 'require_second_factor']);
