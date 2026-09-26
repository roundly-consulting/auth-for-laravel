<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Auth\Rules\PasswordPolicy;

function passes(mixed $password, array $policy = [], ?string $email = null): bool
{
    return Validator::make(['password' => $password], ['password' => [new PasswordPolicy(guardConfig(['passwords' => ['policy' => $policy]]), $email)]])->passes();
}

it('applies the composition rules only when configured', function (): void {
    expect(passes('lowercase-only-words'))->toBeTrue()
        ->and(passes('lowercase-only-words', ['mixed_case' => true]))->toBeFalse()
        ->and(passes('Mixed-Case-Words', ['mixed_case' => true]))->toBeTrue()
        ->and(passes('no-symbols-here1', ['symbols' => false, 'numbers' => true]))->toBeTrue()
        ->and(passes('nosymbolshere1234', ['symbols' => true]))->toBeFalse()
        ->and(passes('1234567890123', ['letters' => true]))->toBeFalse()
        ->and(passes(12345678901))->toBeFalse();
});

it('caps bcrypt at 72 bytes and ignores the cap for other drivers', function (): void {
    $long = str_repeat('a', 73);

    expect(passes($long))->toBeFalse();

    config()->set('hashing.driver', 'argon2id');
    expect(passes($long))->toBeTrue();
});

it('rejects the email local part, unless disabled', function (): void {
    expect(passes('hello-margaret-99', [], 'margaret@example.com'))->toBeFalse()
        ->and(passes('hello-margaret-99', ['not_identifier' => false], 'margaret@example.com'))->toBeTrue()
        ->and(passes('hello-al-is-here', [], 'al@example.com'))->toBeTrue();
});
