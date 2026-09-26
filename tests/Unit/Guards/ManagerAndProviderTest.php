<?php

declare(strict_types=1);

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Exceptions\AccountDisabled;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Guards\AccountUserProvider;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Http\Middleware\EnsureAccountIsActive;
use RoundlyConsulting\Auth\Http\RequestGuard;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\PlainAccount;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use Symfony\Component\HttpFoundation\Response;

it('lists guards and exposes the current guard of a package route', function (): void {
    expect(Authentication::guards())->toBe(['users', 'clients'])
        ->and(Authentication::currentGuard())->toBeNull();

    request()->attributes->set(RequestGuard::ATTRIBUTE, 'clients');

    expect(Authentication::currentGuard()?->name())->toBe('clients')
        ->and(Authentication::guard('clients')->config()->name())->toBe('clients')
        ->and(Authentication::guard()->accounts()->morphClass())->toBe((new User)->getMorphClass());
});

it('knows which guards registered routes', function (): void {
    $manager = app(AuthenticationManager::class);

    expect($manager->routesRegistered('users'))->toBeTrue()
        ->and(fn () => $manager->markRoutesRegistered('users'))->toThrow(AuthenticationMisconfigured::class);
});

it('never resolves a disabled or remembered account', function (): void {
    $provider = Auth::createUserProvider('users');
    $user = User::factory()->create();

    expect($provider)->toBeInstanceOf(AccountUserProvider::class)
        ->and($provider->guard()->name())->toBe('users')
        ->and($provider->retrieveById($user->getKey())?->getAuthIdentifier())->toBe($user->getKey())
        ->and($provider->retrieveByToken($user->getKey(), 'remember'))->toBeNull();

    $provider->updateRememberToken($user, 'x');
    $user->forceFill(['disabled_at' => now()])->save();

    expect($provider->retrieveById($user->getKey()))->toBeNull();
});

it('requires a guard key on the provider config', function (): void {
    config()->set('auth.providers.broken', ['driver' => 'authentication']);

    Auth::createUserProvider('broken');
})->throws(AuthenticationMisconfigured::class);

it('stops a disabled account with the active middleware', function (): void {
    $user = User::factory()->disabled()->create();
    $request = Request::create('/');
    $request->setUserResolver(fn (): User => $user);

    (new EnsureAccountIsActive)->handle($request, fn (): Response => new Response('ok'), 'users');
})->throws(AccountDisabled::class);

it('needs an authenticated request for the current token', function (): void {
    CurrentToken::fromRequest(Request::create('/'), app(GuardRegistry::class)->get('users'));
})->throws(AuthenticationException::class);

it('invalidates through the guard context', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $tokens = Authentication::guard('users')->invalidate($user, InvalidationReason::PasswordChanged, CurrentToken::fromClaims(claimsOf($pair)), new SessionContext);

    expect($tokens)->not->toBeNull()
        ->and(Authentication::guard('users')->invalidate($user, InvalidationReason::PasskeyChanged))->toBeNull();
});

it('narrows only real models with the right contracts', function (): void {
    $plain = new PlainAccount;

    expect(fn () => AccountModels::twoFactor($plain))->toThrow(AuthenticationMisconfigured::class)
        ->and(fn () => AccountModels::passkeys($plain))->toThrow(AuthenticationMisconfigured::class);
});
