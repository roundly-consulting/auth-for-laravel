<?php

declare(strict_types=1);

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\ConsumeOneTimeToken;
use RoundlyConsulting\Auth\Actions\Registration\CreateAccount;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\CreatesAccounts;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Jwt\Events\UserTokenIssued;
use RoundlyConsulting\Jwt\Facades\Jwt;
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
