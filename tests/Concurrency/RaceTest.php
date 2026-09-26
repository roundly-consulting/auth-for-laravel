<?php

declare(strict_types=1);

use Illuminate\Database\UniqueConstraintViolationException;
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
