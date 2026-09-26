<?php

declare(strict_types=1);

use Illuminate\Hashing\HashManager;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Support\DummyPasswordHash;
use RoundlyConsulting\Auth\Tests\Fixtures\CountingHasher;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Structural, not wall-clock: every path performs exactly one real hash check.
 */
function countingHasher(): CountingHasher
{
    $hasher = new CountingHasher(app(HashManager::class)->driver('bcrypt'));
    Hash::swap($hasher);

    return $hasher;
}

it('checks exactly one hash — the dummy — for unknown and passwordless accounts', function (string $identifier): void {
    $hasher = countingHasher();

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($identifier, 'guess'), sessionContext()))->toThrow(InvalidCredentials::class)
        ->and($hasher->checked)->toBe([DummyPasswordHash::get()]);
})->with([
    'unknown' => ['ghost@example.com'],
    'passwordless' => [fn (): string => User::factory()->passwordless()->create()->email],
]);

it('checks the real hash exactly once for a known account', function (): void {
    $user = User::factory()->create();
    $hasher = countingHasher();

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'guess'), sessionContext()))->toThrow(InvalidCredentials::class)
        ->and($hasher->checked)->toBe([(string) $user->getAttribute('password')]);
});

it('reuses one dummy hash per process', function (): void {
    DummyPasswordHash::flush();

    expect(DummyPasswordHash::get())->toBe(DummyPasswordHash::get())
        ->and(Hash::info(DummyPasswordHash::get())['algoName'])->toBe('bcrypt');
});
