<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Postgres (and SQLite) compare case-sensitively; MySQL's default collation does not.
 * Normalising on write keeps package-created rows consistent; legacy mixed-case rows
 * need `case_insensitive_lookup`.
 */
it('finds a legacy mixed-case address only with the case-insensitive lookup', function (): void {
    User::factory()->create(['email' => 'Legacy.Case@Example.com']);

    expect(fn () => Authentication::guard('users')->attempt(new PasswordCredentials('legacy.case@example.com', 'correct-horse-battery'), sessionContext()))
        ->toThrow(InvalidCredentials::class);

    $this->configureGuard('users', ['identifier.case_insensitive_lookup' => true]);

    expect(Authentication::guard('users')->attempt(new PasswordCredentials('LEGACY.case@example.com', 'correct-horse-battery'), sessionContext())->isAuthenticated())->toBeTrue();
})->skip(fn (): bool => DriverMatrix::driver() === 'mysql', 'mysql compares case-insensitively by collation');

it('reads jsonb context and payload columns back', function (): void {
    $user = User::factory()->create();
    enableTotp($user);

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

    expect(LoginChallenge::query()->sole()->contextValue('amr'))->toBe(['pwd']);
});
