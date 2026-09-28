<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Events\PasskeyAdded;
use RoundlyConsulting\Auth\Events\PasskeyRemoved;
use RoundlyConsulting\Auth\Exceptions\LastCredential;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\PasskeyNotFound;
use RoundlyConsulting\Auth\Exceptions\PasskeyRegistrationFailed;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;

beforeEach(function (): void {
    Notification::fake();
});

it('registers, lists, renames and removes a passkey', function (): void {
    Event::fake([PasskeyAdded::class, PasskeyRemoved::class]);
    $user = User::factory()->create();
    $passkeys = Authentication::guard('users')->passkeys();

    $registered = $passkeys->register($user, VirtualAuthenticator::es256()->register($passkeys->registrationOptions($user)), 'Laptop', currentTokenOf(issuePair($user)), sessionContext());
    $second = $passkeys->register($user, VirtualAuthenticator::es256()->register($passkeys->registrationOptions($user)));

    expect($registered->passkey->name)->toBe('Laptop')
        ->and($registered->tokens)->toBeNull() // passkey_changed defaults to `none`
        ->and($passkeys->all($user)->pluck('id')->all())->toBe([$second->passkey->getKey(), $registered->passkey->getKey()])
        ->and($passkeys->rename($user, $registered->passkey, 'Work laptop')->name)->toBe('Work laptop')
        ->and($passkeys->rename($user, (int) $second->passkey->getKey(), 'Phone')->name)->toBe('Phone')
        ->and($passkeys->remove($user, $registered->passkey))->toBeNull()
        ->and($passkeys->remove($user, (int) $second->passkey->getKey()))->toBeNull()
        ->and($passkeys->all($user))->toBeEmpty();

    Event::assertDispatchedTimes(PasskeyAdded::class, 2);
    Event::assertDispatchedTimes(PasskeyRemoved::class, 2);
});

it('refuses a passkey of another account on the same guard', function (): void {
    $user = User::factory()->create();
    $theirs = addPasskey(User::factory()->create());

    expect(fn () => Authentication::passkeys()->rename($user, $theirs, 'mine now'))->toThrow(PasskeyNotFound::class)
        ->and(fn () => Authentication::passkeys()->remove($user, (int) $theirs->getKey()))->toThrow(PasskeyNotFound::class)
        ->and($theirs->fresh())->not->toBeNull();
});

it('keeps the last way in and the guard mode', function (): void {
    $this->configureGuard('users', ['login.password' => false, 'login.magic_link' => false, 'login.email_otp' => false]);
    $user = User::factory()->create();
    $only = addPasskey($user);

    expect(fn () => Authentication::passkeys()->remove($user, $only))->toThrow(LastCredential::class)
        ->and(fn () => Authentication::guard('clients')->passkeys()->registrationOptions(Client::factory()->create()))->toThrow(LoginMethodDisabled::class);
});

it('reports a response the authenticator library refuses', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();

    // Options for another account: the response cannot be stored for this one.
    $response = VirtualAuthenticator::es256()->register(Authentication::passkeys()->registrationOptions($other));

    expect(fn () => Authentication::passkeys()->register($user, $response))->toThrow(PasskeyRegistrationFailed::class);
});
