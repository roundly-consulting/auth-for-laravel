<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomInvitation;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomLoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomLoginChallenge;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomOneTimeToken;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

it('builds the configured challenge from the factory', function (): void {
    expect(LoginChallenge::factory()->create()::class)->toBe(CustomLoginChallenge::class);
});

it('builds the configured one-time token from the factory', function (): void {
    expect(OneTimeToken::factory()->create()::class)->toBe(CustomOneTimeToken::class);
});

it('builds the configured invitation from the factory', function (): void {
    expect(Invitation::factory()->create()::class)->toBe(CustomInvitation::class);
});

it('builds the configured login activity from the factory', function (): void {
    $activity = LoginActivity::factory()->forAccount(User::factory()->create())->create();

    expect($activity::class)->toBe(CustomLoginActivity::class);
});
