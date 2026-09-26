<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomInvitation;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomLoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomLoginChallenge;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomOneTimeToken;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('creates challenges as the host subclass', function (): void {
    $user = User::factory()->create();
    enableTotp($user);

    expect('authentication.models.challenge')->toHonourModelSwap(CustomLoginChallenge::class, function () use ($user) {
        Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext());

        return Models::challenges()->get();
    });
});

it('creates one-time tokens as the host subclass', function (): void {
    Notification::fake();
    $user = User::factory()->create();

    expect('authentication.models.one_time_token')->toHonourModelSwap(CustomOneTimeToken::class, function () use ($user) {
        Authentication::guard('users')->requestMagicLink($user->email, sessionContext());

        return Models::oneTimeTokens()->get();
    });
});

it('creates invitations as the host subclass', function (): void {
    Notification::fake();

    expect('authentication.models.invitation')->toHonourModelSwap(CustomInvitation::class, fn () => Authentication::guard('users')->invite(new InvitationData('someone@example.com')));
});

it('records activity as the host subclass', function (): void {
    expect('authentication.models.login_activity')->toHonourModelSwap(CustomLoginActivity::class, function () {
        try {
            Authentication::guard('users')->attempt(new PasswordCredentials('ghost@example.com', 'x'), sessionContext());
        } catch (Throwable) {
            // the failure is what gets recorded
        }

        return Models::loginActivities()->get();
    });
});
