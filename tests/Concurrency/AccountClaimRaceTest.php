<?php

declare(strict_types=1);

use Illuminate\Hashing\HashManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Login\SecureClaimedAccount;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Events\AccountClaimed;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\Fixtures\ReentrantHasher;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

/**
 * `verification.secure_on_email_login` under interleaving: the owner's claim against the
 * squatter's password login, against a second claim, and against a password written after
 * the claiming login loaded the account.
 */
beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['login.magic_link' => true, 'verification.secure_on_email_login' => true]);
});

function ownerClaims(User $user): void
{
    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());
    Authentication::guard('users')->consumeMagicLink(tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url), sessionContext());
}

it('lets no session of a password login outlive a claim that landed while it was hashing', function (): void {
    $user = User::factory()->unverified()->create();
    $fired = false;
    $claim = static function () use ($user, &$fired): void {
        if (! $fired) {
            $fired = true;
            ownerClaims($user->fresh() ?? $user);
        }
    };

    // The squatter's login loaded the account (and its password hash) before the claim.
    $hashing = app(HashManager::class);
    Hash::swap(new ReentrantHasher($hashing->driver('bcrypt'), static fn () => $claim(), 2));
    $result = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());
    Hash::swap($hashing);

    expect($fired)->toBeTrue()
        ->and($result->isAuthenticated())->toBeTrue()
        ->and($user->fresh()?->hasPassword())->toBeFalse();

    test()->getJson('/users/auth/me', bearer($result->tokens))->assertUnauthorized();
    test()->postJson('/users/auth/refresh', ['refresh_token' => $result->tokens->refreshToken], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');

    // Only the owner's session is left.
    expect(RefreshTokens::sessions($user)->all())->toHaveCount(1);
});

it('secures once when two email logins claim the same account', function (): void {
    Event::fake([AccountClaimed::class]);
    $user = User::factory()->unverified()->create();
    // The second login loaded the account while it was still unverified.
    $stale = User::query()->findOrFail($user->getKey());

    ownerClaims($user);
    $first = RefreshTokens::sessions($user)->all();

    $claimed = app(SecureClaimedAccount::class)->execute(app(GuardRegistry::class)->get('users'), $stale, LoginMethod::MagicLink, sessionContext());

    expect($claimed)->toBeFalse()
        ->and($stale->hasVerifiedEmail())->toBeTrue()
        // The first login's fresh session survives the second claim.
        ->and(RefreshTokens::sessions($user)->all()->modelKeys())->toBe($first->modelKeys());
    Event::assertDispatchedTimes(AccountClaimed::class, 1);
});

it('removes a password written after the claiming login loaded the account', function (): void {
    Event::fake([AccountClaimed::class]);
    $user = User::factory()->unverified()->passwordless()->create();
    $stale = User::query()->findOrFail($user->getKey());

    // The squatter set a password in between.
    User::query()->whereKey($user->getKey())->update(['password' => Hash::make('a-squatters-passphrase')]);

    $claimed = app(SecureClaimedAccount::class)->execute(app(GuardRegistry::class)->get('users'), $stale, LoginMethod::MagicLink, sessionContext());

    expect($claimed)->toBeTrue()
        ->and($user->fresh()?->hasPassword())->toBeFalse();
    Event::assertDispatched(AccountClaimed::class, fn (AccountClaimed $event): bool => $event->passwordRemoved);
});
