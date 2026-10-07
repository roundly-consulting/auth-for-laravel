<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Enums\InvitationStatus;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('declares each model swappable through its config key', function (): void {
    expect(LoginChallenge::class)->toBeSwappableVia('authentication.models.challenge')
        ->and(OneTimeToken::class)->toBeSwappableVia('authentication.models.one_time_token')
        ->and(Invitation::class)->toBeSwappableVia('authentication.models.invitation')
        ->and(LoginActivity::class)->toBeSwappableVia('authentication.models.login_activity');
});

it('never serialises a secret hash', function (): void {
    expect(LoginChallenge::factory()->create()->toArray())->not->toHaveKeys(['token_hash', 'fingerprint_hash'])
        ->and(OneTimeToken::factory()->create()->toArray())->not->toHaveKeys(['token_hash', 'code_hash', 'fingerprint_hash'])
        ->and(Invitation::factory()->create(['token_hash' => str_repeat('a', 64)])->toArray())->not->toHaveKey('token_hash')
        ->and(User::factory()->create()->toArray())->not->toHaveKeys(['token_version', 'locked_until', 'disabled_reason', 'failed_login_count', 'password', 'two_factor_secret']);
});

/**
 * Regression (chat review V-1): the trait hid four sensitive columns by their configured names
 * but not the password, so a renamed `columns.password` serialised the hash next to a model's
 * stock `$hidden = ['password']` (a host `return $user;`).
 */
it('never serialises the password hash under a renamed password column', function (): void {
    config()->set('authentication.columns.password', 'password_hash');

    $user = (new User)->forceFill(['email' => 'renamed@example.com', 'password_hash' => '$2y$04$hash']);

    expect($user->toArray())->not->toHaveKey('password_hash')->toHaveKey('email', 'renamed@example.com')
        ->and($user->hasPassword())->toBeTrue();
});

it('derives the invitation status and filters by it', function (): void {
    CarbonImmutable::setTestNow('2026-09-26 12:00:00');
    Invitation::factory()->create();
    Invitation::factory()->accepted()->create();
    Invitation::factory()->revoked()->create();
    Invitation::factory()->expired()->create();

    foreach (InvitationStatus::cases() as $status) {
        $matching = Invitation::query()->withStatus($status)->get();

        expect($matching)->toHaveCount(1)
            ->and($matching->sole()->status())->toBe($status);
    }

    CarbonImmutable::setTestNow();
});

it('resolves the account relations', function (): void {
    $user = User::factory()->create();

    expect(LoginChallenge::factory()->forAccount($user)->create()->account?->is($user))->toBeTrue()
        ->and(OneTimeToken::factory()->forAccount($user)->create()->account?->is($user))->toBeTrue()
        ->and(LoginActivity::factory()->forAccount($user)->create()->account?->is($user))->toBeTrue()
        ->and(Invitation::factory()->create(['account_type' => $user->getMorphClass(), 'account_id' => $user->getKey(), 'inviter_type' => $user->getMorphClass(), 'inviter_id' => $user->getKey()])->inviter?->is($user))->toBeTrue()
        ->and(OneTimeToken::factory()->create(['payload' => ['old_email' => 'a@b.c']])->payloadValue('old_email'))->toBe('a@b.c')
        ->and(Invitation::factory()->create(['payload' => ['role' => 'x']])->payloadValue('role'))->toBe('x');
});

it('reads a challenge\'s stored state defensively', function (): void {
    $challenge = LoginChallenge::factory()->create([
        'required_steps' => [['step' => 'nope'], 'garbage', ['step' => 'passkey', 'methods' => ['passkey', 'nope']]],
        'completed_steps' => ['second_factor', 'nope', 3],
        'context' => ['amr' => ['pwd', 'nope', 'pwd']],
    ]);

    expect(array_map(fn ($r) => $r->step->value, $challenge->remaining()))->toBe(['passkey'])
        ->and($challenge->remaining()[0]->methods)->toHaveCount(1)
        ->and(array_map(fn ($s) => $s->value, $challenge->completed()))->toBe(['second_factor'])
        ->and($challenge->authMethods())->toHaveCount(1)
        ->and($challenge->attemptsLeft())->toBe(5);
});
