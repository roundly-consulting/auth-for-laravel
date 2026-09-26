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
use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Jwt\Events\UserTokenIssued;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenRedeemed;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;

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
    $minted = interleaveRefresh(static fn () => RefreshToken::redeem($first->refreshToken));

    test()->postJson('/users/auth/refresh', ['refresh_token' => $second], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');

    expect($minted)->toHaveCount(1)
        ->and(Jwt::denylist()->has($minted[0]))->toBeTrue()
        ->and(RefreshToken::listFor($user))->toBeEmpty();
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
        ->and(RefreshToken::listFor($user))->toBeEmpty();
});
