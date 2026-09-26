<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Events\RefreshTokenReuseReported;
use RoundlyConsulting\Auth\Exceptions\InvalidRefreshToken;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Listeners\ReportRefreshTokenReuse;
use RoundlyConsulting\Auth\Notifications\SuspiciousSessionNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;

it('reports reuse of a rotated refresh token with the guard and account, and tells the owner', function (): void {
    Notification::fake();
    Event::fake([RefreshTokenReuseReported::class]);
    Event::listen(RefreshTokenReuseDetected::class, ReportRefreshTokenReuse::class);
    $user = User::factory()->create();
    $pair = issuePair($user);

    $rotated = Authentication::guard('users')->refresh($pair->refreshToken, sessionContext());

    expect(fn () => Authentication::guard('users')->refresh($pair->refreshToken, sessionContext()))->toThrow(InvalidRefreshToken::class)
        ->and(fn () => Authentication::guard('users')->refresh($rotated->refreshToken, sessionContext()))->toThrow(InvalidRefreshToken::class);

    Event::assertDispatched(RefreshTokenReuseReported::class, fn (RefreshTokenReuseReported $event): bool => $event->guard === 'users' && $event->sessionId === $pair->sessionId);
    Notification::assertSentTo($user, SuspiciousSessionNotification::class);
});

it('ignores reuse on owners it does not know', function (): void {
    Event::fake([RefreshTokenReuseReported::class]);

    $listener = app(ReportRefreshTokenReuse::class);
    $listener->handle(new RefreshTokenReuseDetected('family', 'App\Models\Stranger', 1));
    $listener->handle(new RefreshTokenReuseDetected('family', (new User)->getMorphClass(), 999));

    Event::assertNotDispatched(RefreshTokenReuseReported::class);
});
