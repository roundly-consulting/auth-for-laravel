<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;

it('prunes what is past expiry or retention, and nothing else', function (): void {
    CarbonImmutable::setTestNow('2026-09-26 12:00:00');

    LoginChallenge::factory()->create(['expires_at' => '2026-09-25 11:59:59']);
    LoginChallenge::factory()->create(['expires_at' => '2026-09-25 12:00:01']);
    OneTimeToken::factory()->create(['expires_at' => '2026-09-20 00:00:00']);
    tap(OneTimeToken::factory()->create(['expires_at' => '2026-09-20 00:00:00']))->delete();
    OneTimeToken::factory()->create();
    Invitation::factory()->create(['accepted_at' => '2026-05-01 00:00:00']);
    Invitation::factory()->create();
    LoginActivity::factory()->create(['created_at' => '2026-06-01 00:00:00']);
    LoginActivity::factory()->create(['guard' => 'removed-guard', 'created_at' => '2026-06-01 00:00:00']);
    LoginActivity::factory()->create();

    $this->artisan('authentication:prune')
        ->expectsOutputToContain('Pruned 6 rows.')
        ->assertSuccessful();

    expect(LoginChallenge::query()->count())->toBe(1)
        ->and(OneTimeToken::query()->withTrashed()->count())->toBe(1)
        ->and(Invitation::query()->count())->toBe(1)
        ->and(LoginActivity::query()->count())->toBe(1);

    CarbonImmutable::setTestNow();
});

it('honours --days and validates it', function (): void {
    LoginActivity::factory()->create(['created_at' => now()->subDays(3)]);

    $this->artisan('authentication:prune', ['--days' => '5'])->assertSuccessful();
    expect(LoginActivity::query()->count())->toBe(1);

    $this->artisan('authentication:prune', ['--days' => '2'])->assertSuccessful();
    expect(LoginActivity::query()->count())->toBe(0);

    $this->artisan('authentication:prune', ['--days' => 'soon'])->assertFailed();
});

it('works through model:prune too', function (): void {
    LoginChallenge::factory()->create(['expires_at' => now()->subDays(2)]);

    $this->artisan('model:prune', ['--model' => [LoginChallenge::class]])->assertSuccessful();

    expect(LoginChallenge::query()->withTrashed()->count())->toBe(0);
});
