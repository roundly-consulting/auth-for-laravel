<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Exceptions\RefreshSuperseded;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use Symfony\Component\HttpFoundation\Response;

/*
 * Two servers refreshing the same session at once: the loser, inside
 * `refresh-tokens.rotation.grace`, gets 409 `refresh_superseded` — keep the winner's token,
 * don't sign out — instead of 401 `refresh_invalid`.
 */
beforeEach(function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class]);
});

afterEach(fn () => CarbonImmutable::setTestNow());

/**
 * @return TestResponse<Response>
 */
function refreshOverHttp(string $token): TestResponse
{
    return test()->postJson('/users/auth/refresh', ['refresh_token' => $token], ['User-Agent' => 'PestBrowser/1.0']);
}

it('answers a refresh superseded inside the grace with 409, keeping the session alive', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $winner = refreshOverHttp($pair->refreshToken)->assertOk()->json('refresh_token');

    refreshOverHttp($pair->refreshToken)
        ->assertStatus(409)
        ->assertJsonPath('code', 'refresh_superseded')
        ->assertJsonPath('message', 'This session was just refreshed elsewhere; use the newest token.');

    // Nothing revoked, no reuse reported: the winner's token keeps the session going.
    expect(RefreshTokens::sessions($user)->all())->toHaveCount(1);
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);

    refreshOverHttp($winner)->assertOk()->assertJsonPath('session_id', $pair->sessionId);
});

it('records the superseded refresh as a failed token refresh with its own reason', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext);

    expect(fn () => Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext))
        ->toThrow(RefreshSuperseded::class);

    $activity = LoginActivity::query()->where('type', 'refresh')->sole();

    expect($activity->outcome->value)->toBe('failed_token')
        ->and($activity->reason)->toBe('superseded');
});

it('still counts a superseded refresh towards the refresh throttle', function (): void {
    $this->configureGuard('users', ['throttle.refresh.max' => 2]);

    $user = User::factory()->create();
    $pair = issuePair($user);

    refreshOverHttp($pair->refreshToken)->assertOk();
    refreshOverHttp($pair->refreshToken)->assertStatus(409);
    refreshOverHttp($pair->refreshToken)->assertStatus(429)->assertJsonPath('code', 'too_many_attempts');
});

it('answers a duplicate after the grace with 401 and ends the session', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

    $user = User::factory()->create();
    $pair = issuePair($user);

    refreshOverHttp($pair->refreshToken)->assertOk();

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(31));

    refreshOverHttp($pair->refreshToken)
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');

    expect(RefreshTokens::sessions($user)->all())->toBeEmpty()
        ->and(LoginActivity::query()->where('type', 'refresh')->sole()->reason)->toBe('unknown');
    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
});

it('answers a token revoked by logout with 401, inside the grace too', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    test()->postJson('/users/auth/logout', [], bearer($pair))->assertNoContent();

    refreshOverHttp($pair->refreshToken)
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');
});

it('answers a superseded token whose session was logged out meanwhile with 401', function (): void {
    $user = User::factory()->create();
    $pair = issuePair($user);

    $winner = Authentication::guard('users')->refresh($pair->refreshToken, new SessionContext);
    test()->postJson('/users/auth/logout', [], bearer($winner))->assertNoContent();

    refreshOverHttp($pair->refreshToken)
        ->assertStatus(401)
        ->assertJsonPath('code', 'refresh_invalid');
});

it('translates the message in English and Slovak', function (string $locale, string $message): void {
    app()->setLocale($locale);

    expect((new RefreshSuperseded)->getMessage())->toBe($message);
})->with([
    'en' => ['en', 'This session was just refreshed elsewhere; use the newest token.'],
    'sk' => ['sk', 'Táto relácia bola práve obnovená inde; použite najnovší token.'],
]);
