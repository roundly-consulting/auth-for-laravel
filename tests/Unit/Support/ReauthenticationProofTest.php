<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationProof;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('classifies re-authentication methods by whether they prove a second factor', function (): void {
    $second = array_values(array_filter(ReauthenticationMethod::cases(), static fn (ReauthenticationMethod $method): bool => $method->isSecondFactor()));

    expect($second)->toBe([ReauthenticationMethod::Totp, ReauthenticationMethod::RecoveryCode, ReauthenticationMethod::Passkey]);
});

it('records the method with the time and ignores a marker without one', function (): void {
    $marker = app(ReauthenticationMarker::class);
    $at = CarbonImmutable::parse('2026-09-26 10:00:00');

    $marker->put('users', 'sid-1', new ReauthenticationProof(ReauthenticationMethod::Totp, $at), 60);

    expect($marker->proof('users', 'sid-1'))->toEqual(new ReauthenticationProof(ReauthenticationMethod::Totp, $at))
        ->and($marker->proof('users', 'sid-2'))->toBeNull();

    cache()->put('authentication:reauth:users:legacy', $at->getTimestamp(), 60);
    cache()->put('authentication:reauth:users:unknown', ['method' => 'sms', 'at' => $at->getTimestamp()], 60);

    expect($marker->proof('users', 'legacy'))->toBeNull()
        ->and($marker->proof('users', 'unknown'))->toBeNull();

    $marker->forget('users', 'sid-1');
    expect($marker->proof('users', 'sid-1'))->toBeNull();
});

it('requires a second-factor proof only from accounts with one, and only when the guard says so', function (): void {
    $user = User::factory()->create();

    expect(ReauthenticationMethods::requireSecondFactor(guardConfig(), $user))->toBeFalse();

    enableTotp($user);

    expect(ReauthenticationMethods::requireSecondFactor(guardConfig(), $user))->toBeTrue()
        ->and(ReauthenticationMethods::requireSecondFactor(guardConfig(['reauthentication' => ['require_second_factor_when_enrolled' => false]]), $user))->toBeFalse()
        ->and(ReauthenticationMethods::requireSecondFactor(guardConfig(['two_factor' => ['mode' => 'off']]), $user))->toBeFalse();
});
