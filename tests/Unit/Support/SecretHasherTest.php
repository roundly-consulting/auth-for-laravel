<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Support\SecretHasher;

it('binds guard and purpose into link MACs, and the address into code MACs', function (): void {
    $hasher = new SecretHasher;

    expect($hasher->link('users', 'magic_link', 't'))->toHaveLength(64)
        ->not->toBe($hasher->link('clients', 'magic_link', 't'))
        ->not->toBe($hasher->link('users', 'password_reset', 't'))
        ->and($hasher->code('users', 'email_otp', 'a@x.test', '123456'))
        ->not->toBe($hasher->code('users', 'email_otp', 'b@x.test', '123456'))
        ->and($hasher->fingerprint('users', 'a', null))->not->toBe($hasher->fingerprint('users', null, 'a'));
});

it('derives its key from the decoded app key unless one is configured', function (): void {
    $derived = (new SecretHasher)->link('users', 'p', 't');

    config()->set('authentication.hash_key', 'a-dedicated-hash-key');
    $dedicated = new SecretHasher;

    expect($dedicated->usesDerivedKey())->toBeFalse()
        ->and($dedicated->link('users', 'p', 't'))->not->toBe($derived);

    config()->set('authentication.hash_key', null);
    config()->set('app.key', 'plain-app-key-without-prefix');

    expect((new SecretHasher)->link('users', 'p', 't'))->not->toBe($derived);
});

it('refuses to work without any key', function (string $appKey): void {
    config()->set('app.key', $appKey);

    (new SecretHasher)->link('users', 'p', 't');
})->with(['', 'base64:***not base64***'])->throws(AuthenticationMisconfigured::class);
