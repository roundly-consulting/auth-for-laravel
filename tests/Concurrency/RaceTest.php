<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Hashing\HashManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\ConsumeOneTimeToken;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\VerifyOneTimeCode;
use RoundlyConsulting\Auth\Actions\Registration\CreateAccount;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\CreatesAccounts;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Events\AccountLocked;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\InvitationSendLimitReached;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\AccountLockedNotification;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Notifications\InvitationNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\Fixtures\ReentrantHasher;
use RoundlyConsulting\Jwt\Events\UserTokenIssued;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenRedeemed;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;

/**
 * Interleaved stale reads: the loser of each race sees the winner's write and gets the
 * uniform error, never a second success.
 */
final class RacingCreator implements CreatesAccounts
{
    public function create(GuardConfig $guard, NewAccountData $data): Account
    {
        // Another request inserted the same address between our check and our insert.
        User::factory()->create(['email' => $data->email]);

        return app(CreateAccount::class)->create($guard, $data);
    }
}

it('lets exactly one consumer claim a link', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());
    $token = tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url);

    // The loser read the row as usable, then the winner claimed it.
    OneTimeToken::query()->update(['consumed_at' => now()]);

    app(ConsumeOneTimeToken::class)->execute('users', OneTimeTokenPurpose::MagicLink, $token, sessionContext());
})->throws(InvalidOneTimeToken::class);

it('maps a registration race on the unique address to the enumeration-safe answer', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['registration.creator' => RacingCreator::class, 'registration.login_after' => false]);

    $result = Authentication::guard('users')->register(new RegistrationData('race@example.com', 'a-long-enough-passphrase', sessionContext()));

    // (The simulated competitor shares our connection, so our rollback also removes it —
    // in production it committed on its own. What matters is the answer.)
    expect($result->status)->toBe(RegistrationStatus::Accepted);
});

it('answers a race with "email taken" when tokens would have been issued', function (): void {
    $this->configureGuard('users', ['registration.creator' => RacingCreator::class]);

    Authentication::guard('users')->register(new RegistrationData('race@example.com', 'a-long-enough-passphrase', sessionContext()));
})->throws(ValidationException::class);

it('never lets the unique index be bypassed', function (): void {
    User::factory()->create(['email' => 'dup@example.com']);

    User::factory()->create(['email' => 'dup@example.com']);
})->throws(UniqueConstraintViolationException::class);

/**
 * Runs `$interleave` once, right after the refresh under test redeemed its token and
 * before it issues the replacement; returns the jtis minted meanwhile.
 *
 * @return ArrayObject<int, string>
 */
function interleaveRefresh(Closure $interleave): ArrayObject
{
    $minted = new ArrayObject;
    $fired = false;

    Event::listen(RefreshTokenRedeemed::class, function () use ($interleave, &$fired): void {
        if (! $fired) {
            $fired = true;
            $interleave();
        }
    });
    Event::listen(UserTokenIssued::class, static function (UserTokenIssued $event) use ($minted): void {
        $minted[] = $event->jti;
    });

    return $minted;
}

it('answers 401 when a refresh loses the race to reuse detection', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $first = issuePair($user);
    $second = Authentication::guard('users')->refresh($first->refreshToken, sessionContext())->refreshToken;

    // A thief replays the already-rotated first token while the owner's refresh is under way.
    $minted = interleaveRefresh(static fn () => RefreshTokens::redeem($first->refreshToken));

    test()->postJson('/users/auth/refresh', ['refresh_token' => $second], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');

    expect($minted)->toHaveCount(1)
        ->and(Jwt::denylist()->has($minted[0]))->toBeTrue()
        ->and(RefreshTokens::sessions($user)->all())->toBeEmpty();
});

it('answers 401 when a logout everywhere lands mid-refresh, leaving no live session', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $pair = issuePair($user);

    $minted = interleaveRefresh(static fn () => Authentication::guard('users')->logoutEverywhere($user->fresh() ?? $user));

    test()->postJson('/users/auth/refresh', ['refresh_token' => $pair->refreshToken], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');

    expect($minted)->toHaveCount(1)
        ->and(Jwt::denylist()->has($minted[0]))->toBeTrue()
        ->and(RefreshTokens::sessions($user)->all())->toBeEmpty();
});

function totpChallenge(User $user): PendingChallenge
{
    $result = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect($result->requiresChallenge())->toBeTrue();

    return $result->challenge;
}

function submitChallengeCode(PendingChallenge $pending, string $code): void
{
    Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::Totp, sessionContext(), $code));
}

it('takes a challenge attempt before checking a code, so overlapping guesses cannot outrun the cap', function (): void {
    // The challenge cap has to hold on its own — the two-factor limiter can be switched off.
    config()->set('two-factor.attempts', null);
    $user = User::factory()->create();
    enableTotp($user);
    $pending = totpChallenge($user);
    $evaluated = 0;
    $refused = 0;

    $guess = static function () use ($pending, &$refused): void {
        try {
            submitChallengeCode($pending, '000000');
        } catch (ChallengeFactorFailed) {
            // A wrong code that was checked.
        } catch (ChallengeInvalid) {
            $refused++;
        }
    };

    // Each checked code fires this before its own request returns: the next guess starts
    // right there, so every guess is in flight at once, like a parallel burst.
    Event::listen(TwoFactorVerificationFailed::class, static function () use (&$evaluated, $guess): void {
        if (++$evaluated < 10) {
            $guess();
        }
    });

    $guess();

    expect($evaluated)->toBe(5)
        ->and($refused)->toBe(1)
        ->and(LoginChallenge::query()->sole()->attempts)->toBe(5)
        ->and(LoginChallenge::query()->sole()->invalidated_reason)->toBe('attempts_exhausted');
});

it('never checks a code while in-flight guesses hold every attempt', function (): void {
    $user = User::factory()->create();
    $secret = enableTotp($user);
    $pending = totpChallenge($user);

    // Five guesses took the attempts and are still being checked.
    LoginChallenge::query()->update(['attempts' => 5]);

    expect(fn () => submitChallengeCode($pending, totpCode($secret)))->toThrow(ChallengeInvalid::class)
        ->and(LoginChallenge::query()->sole()->completed_at)->toBeNull();
});

it('gives the attempt back when the code verifies or was never checked', function (): void {
    $user = User::factory()->create();
    $secret = enableTotp($user);
    config()->set('two-factor.attempts', ['max' => 1, 'decay' => 60]);
    $pending = totpChallenge($user);

    expect(fn () => submitChallengeCode($pending, '000000'))->toThrow(ChallengeFactorFailed::class)
        // The two-factor limiter refuses before checking: the challenge attempt is returned.
        ->and(fn () => submitChallengeCode($pending, '111111'))->toThrow(TooManyAttempts::class)
        ->and(LoginChallenge::query()->sole()->attempts)->toBe(1);

    config()->set('two-factor.attempts', null);
    submitChallengeCode($pending, totpCode($secret));

    expect(LoginChallenge::query()->sole())
        ->attempts->toBe(1)
        ->completed_at->not->toBeNull();
});

it('takes the attempt before checking a forced-enrolment code too', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['two_factor.mode' => 'required']);
    $user = User::factory()->create();
    $pending = totpChallenge($user);
    $setup = Authentication::challenges()->startTwoFactorEnrolment($pending->token, sessionContext());
    $confirm = static fn (string $code) => Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::TotpEnrolment, sessionContext(), $code));

    expect(fn () => $confirm('000000'))->toThrow(ChallengeFactorFailed::class)
        ->and(LoginChallenge::query()->sole()->attempts)->toBe(1);

    LoginChallenge::query()->update(['attempts' => 5]);

    expect(fn () => $confirm(totpCode($setup->secret)))->toThrow(ChallengeInvalid::class)
        ->and($user->fresh()?->hasTwoFactorEnabled())->toBeFalse();

    LoginChallenge::query()->update(['attempts' => 1]);

    expect($confirm(totpCode($setup->secret))->isAuthenticated())->toBeTrue()
        ->and(LoginChallenge::query()->sole()->attempts)->toBe(1);
});

/**
 * Runs `$concurrent` once, right after the `$after`-th query of `$request` whose SQL
 * mentions `$needle` — or after `$request` returned, when it issued fewer. True when
 * `$concurrent` ran while `$request` was still in flight.
 */
function interleaveAfterQuery(string $needle, int $after, Closure $request, Closure $concurrent): bool
{
    $seen = 0;
    $fired = false;

    DB::listen(static function (QueryExecuted $query) use ($needle, $after, $concurrent, &$seen, &$fired): void {
        if (! $fired && str_contains($query->sql, $needle) && ++$seen === $after) {
            $fired = true;
            $concurrent();
        }
    });

    $request();

    if ($fired) {
        return true;
    }

    $fired = true;
    $concurrent();

    return false;
}

function failPassword(User $user): void
{
    try {
        Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'wrong-password'), sessionContext());
    } catch (AuthException) {
        // counted, or refused
    }
}

it('locks and notifies once when concurrent failures reach the threshold together', function (int $start, int $after): void {
    Event::fake([AccountLocked::class]);
    Notification::fake();
    $this->configureGuard('users', ['lockout.enabled' => true, 'lockout.threshold' => 3, 'throttle.login.max' => 100, 'throttle.login_account.max' => 100]);
    $user = User::factory()->create(['failed_login_count' => $start]);

    interleaveAfterQuery('failed_login_count', $after, static fn () => failPassword($user), static fn () => failPassword($user));

    Event::assertDispatchedTimes(AccountLocked::class, 1);
    expect(Notification::sent($user, AccountLockedNotification::class))->toHaveCount(1)
        ->and($user->fresh()?->isLocked())->toBeTrue()
        ->and($user->fresh()?->getAttribute('failed_login_count'))->toBe(0);
})->with(['at threshold - 1' => 2, 'at threshold - 2' => 1])->with([1, 2, 3]);

it('never writes a counter it read back over a concurrent failure', function (int $after): void {
    $this->configureGuard('users', ['lockout.enabled' => true, 'lockout.threshold' => 10, 'throttle.login.max' => 100, 'throttle.login_account.max' => 100]);
    $user = User::factory()->create();

    interleaveAfterQuery('failed_login_count', $after, static fn () => failPassword($user), static fn () => failPassword($user));

    expect($user->fresh()?->getAttribute('failed_login_count'))->toBe(2);
})->with([1, 2, 3]);

it('reports the attempts actually left when a concurrent wrong guess spends the last one', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext());
    $code = (string) sentNotification($user, EmailOtpNotification::class)->data->code;
    $wrong = $code === '000000' ? '111111' : '000000';
    OneTimeToken::query()->update(['attempts' => 3]);

    $guess = static function () use ($user, $wrong): int {
        try {
            app(VerifyOneTimeCode::class)->execute('users', OneTimeTokenPurpose::EmailOtp, (string) $user->email, $wrong, revealAttempts: true);
        } catch (InvalidCode $e) {
            return (int) $e->extra()['attempts_left'];
        }

        return -1;
    };
    $left = [];

    // The concurrent guess runs between this one's read of the row and its own count.
    interleaveAfterQuery(Tables::oneTimeTokens(), 1, static function () use ($guess, &$left): void {
        $left['first'] = $guess();
    }, static function () use ($guess, &$left): void {
        $left['concurrent'] = $guess();
    });

    expect($left)->toBe(['concurrent' => 1, 'first' => 0])
        ->and(OneTimeToken::query()->sole())
        ->attempts->toBe(5)
        ->invalidated_at->not->toBeNull();
});

it('keeps the cooldown, the cap and the count when two resends read the invitation before either wrote', function (int $maxSends, int $cooldown, ?string $refused, int $mails): void {
    Notification::fake();
    $this->configureGuard('users', ['invitations.max_sends' => $maxSends, 'invitations.resend_cooldown' => $cooldown]);
    Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com'));
    $this->travel(5)->minutes();

    // Both requests loaded the row (one send, five minutes ago) before either resent.
    $first = Invitation::query()->sole();
    $second = Invitation::query()->sole();

    Authentication::guard('users')->invitations()->resend($first);
    $resend = static fn () => Authentication::guard('users')->invitations()->resend($second);

    $refused === null ? $resend() : expect($resend)->toThrow($refused);

    Notification::assertSentOnDemandTimes(InvitationNotification::class, $mails);
    expect(Invitation::query()->sole()->send_count)->toBe($mails);
})->with([
    'the cooldown' => [5, 60, TooManyAttempts::class, 2],
    'the cap' => [2, 0, InvitationSendLimitReached::class, 2],
    'neither: both count' => [5, 0, null, 3],
]);

it('lets no session outlive an invalidation that raced its login', function (string $path): void {
    Notification::fake();
    $user = User::factory()->create();
    $fired = false;
    $reset = static function () use ($user, &$fired): void {
        if (! $fired) {
            $fired = true;
            Authentication::guard('users')->passwords()->set($user->fresh() ?? $user, 'a-brand-new-passphrase');
        }
    };

    if ($path === 'direct login') {
        // The reset lands while the login is still hashing against the account it loaded.
        $hashing = app(HashManager::class);
        Hash::swap(new ReentrantHasher($hashing->driver('bcrypt'), static fn () => $reset(), 2));
        $result = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());
        Hash::swap($hashing);
    } else {
        $secret = enableTotp($user);
        $pending = totpChallenge($user);
        // The reset lands right after the finalize claimed the challenge, before the pair is issued.
        Event::listen(UserTokenIssued::class, static fn () => $reset());
        $result = Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::Totp, sessionContext(), totpCode($secret)));
    }

    expect($fired)->toBeTrue()
        ->and($result->isAuthenticated())->toBeTrue();

    test()->getJson('/users/auth/me', bearer($result->tokens))->assertUnauthorized();
    test()->postJson('/users/auth/refresh', ['refresh_token' => $result->tokens->refreshToken], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');

    expect(RefreshTokens::sessions($user)->all())->toBeEmpty();
})->with(['direct login', 'challenge finalize']);

it('never lets a passkey step that lost the race pop the step after it', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required', 'two_factor.passkey_satisfies_required' => false]);
    $user = User::factory()->create();
    enableTotp($user);
    $authenticator = registerVirtualPasskey($user);
    $pending = totpChallenge($user);
    $complete = static fn ($assertion) => Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::Passkey, sessionContext(), assertion: $assertion));
    $assertion = $authenticator->assert(Authentication::challenges()->passkeyOptions($pending->token, sessionContext()));
    $concurrent = null;

    // While this request verifies its assertion, another one restarts the ceremony and completes the step.
    Event::listen(PasskeyAuthenticated::class, static function () use (&$concurrent, $authenticator, $pending, $complete): void {
        if ($concurrent === null) {
            $concurrent = false;
            $concurrent = $complete($authenticator->assert(Authentication::challenges()->passkeyOptions($pending->token, sessionContext())));
        }
    });

    expect(fn () => $complete($assertion))->toThrow(ChallengeInvalid::class)
        ->and($concurrent?->requiresChallenge())->toBeTrue()
        ->and(LoginChallenge::query()->sole())
        ->completed_at->toBeNull()
        ->completed()->toBe([ChallengeStep::Passkey]);
});

it('never lets a passkey enrolment that lost the race pop the enrolment after it', function (): void {
    Notification::fake();
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required', 'two_factor.passkey_satisfies_required' => false]);
    $user = User::factory()->create();
    $pending = totpChallenge($user);
    $complete = static fn ($attestation) => Authentication::challenges()->complete(new ChallengeFactorData($pending->token, FactorMethod::PasskeyEnrolment, sessionContext(), attestation: $attestation));
    $attestation = VirtualAuthenticator::es256()->register(Authentication::challenges()->passkeyEnrolmentOptions($pending->token, sessionContext()));
    $outcome = null;
    $concurrent = null;

    // Right after this request checked the account has no passkey yet, another one restarts the
    // ceremony and completes the enrolment.
    interleaveAfterQuery((new Passkey)->getTable(), 1, static function () use (&$outcome, $complete, $attestation): void {
        try {
            $outcome = $complete($attestation);
        } catch (ChallengeInvalid $e) {
            $outcome = $e;
        }
    }, static function () use (&$concurrent, $pending, $complete): void {
        $concurrent = $complete(VirtualAuthenticator::es256()->register(Authentication::challenges()->passkeyEnrolmentOptions($pending->token, sessionContext())));
    });

    expect($outcome)->toBeInstanceOf(ChallengeInvalid::class)
        ->and($concurrent?->requiresChallenge())->toBeTrue()
        ->and($user->fresh()?->hasTwoFactorEnabled())->toBeFalse()
        ->and(LoginChallenge::query()->sole())
        ->completed_at->toBeNull()
        ->completed()->toBe([ChallengeStep::EnrolPasskey]);
});
