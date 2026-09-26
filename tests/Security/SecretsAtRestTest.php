<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Notifications\MagicLinkNotification;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * After real flows, no plaintext secret sits in any package table or dispatched event.
 */
it('stores and announces only hashes', function (): void {
    Notification::fake();
    $recorded = [];
    Event::listen('RoundlyConsulting\Auth\Events\*', function (string $name, array $payload) use (&$recorded): void {
        $recorded[] = serialize($payload);
    });

    $user = User::factory()->create();
    enableTotp($user);

    Authentication::guard('users')->requestMagicLink($user->email, sessionContext());
    Authentication::guard('users')->requestEmailOtp($user->email, sessionContext());
    $challenge = Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'correct-horse-battery'), sessionContext())->challenge;
    $pair = issuePair($user);

    $secrets = [
        tokenFromUrl(sentNotification($user, MagicLinkNotification::class)->data->url),
        (string) sentNotification($user, EmailOtpNotification::class)->data->code,
        $challenge->token,
        'correct-horse-battery',
        $pair->refreshToken,
    ];

    $rows = '';

    foreach ([Tables::challenges(), Tables::oneTimeTokens(), Tables::invitations(), Tables::loginActivities(), 'refresh_tokens', 'users'] as $table) {
        $rows .= json_encode(DB::table($table)->get());
    }

    foreach ($secrets as $secret) {
        expect($rows)->not->toContain($secret)
            ->and(implode('', $recorded))->not->toContain($secret);
    }
});
