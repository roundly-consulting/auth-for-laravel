<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Auth\Events\LocaleUpdated;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    $this->configureGuard('users', ['locale.supported' => ['en', 'sk']]);
});

it('updates the locale and timezone', function (): void {
    Event::fake([LocaleUpdated::class]);
    $user = User::factory()->create();

    $this->patchJson('/users/auth/locale', ['locale' => 'sk', 'timezone' => 'Europe/Bratislava'], bearer(issuePair($user)))
        ->assertOk()
        ->assertExactJson(['locale' => 'sk', 'timezone' => 'Europe/Bratislava']);

    expect($user->fresh()?->preferredLocale())->toBe('sk');
    Event::assertDispatched(LocaleUpdated::class);
});

it('changes only the fields the client sent, and clears a field sent as null', function (): void {
    Event::fake([LocaleUpdated::class]);
    $user = User::factory()->create(['locale' => 'en', 'timezone' => 'Europe/Bratislava']);
    $headers = bearer(issuePair($user));

    $this->patchJson('/users/auth/locale', ['locale' => 'sk'], $headers)
        ->assertOk()
        ->assertExactJson(['locale' => 'sk', 'timezone' => 'Europe/Bratislava']);

    $this->patchJson('/users/auth/locale', ['timezone' => 'Europe/Prague'], $headers)
        ->assertOk()
        ->assertExactJson(['locale' => 'sk', 'timezone' => 'Europe/Prague']);

    $this->patchJson('/users/auth/locale', [], $headers)
        ->assertOk()
        ->assertExactJson(['locale' => 'sk', 'timezone' => 'Europe/Prague']);

    $this->patchJson('/users/auth/locale', ['timezone' => null], $headers)
        ->assertOk()
        ->assertExactJson(['locale' => 'sk', 'timezone' => null]);

    expect($user->fresh()?->accountLocale())->toBe('sk')
        ->and($user->fresh()?->accountTimezone())->toBeNull();
    Event::assertDispatched(LocaleUpdated::class, fn (LocaleUpdated $event): bool => $event->locale === 'sk' && $event->timezone === 'Europe/Prague');
});

it('rejects unsupported locales and unknown timezones', function (): void {
    $this->patchJson('/users/auth/locale', ['locale' => 'fr', 'timezone' => 'Mars/Olympus'], bearer(issuePair(User::factory()->create())))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['locale', 'timezone']);
});

it('ignores the timezone when the guard does not keep one', function (): void {
    $this->configureGuard('users', ['locale.timezone' => false]);
    $user = User::factory()->create();

    $this->patchJson('/users/auth/locale', ['locale' => 'en', 'timezone' => 'Europe/Bratislava'], bearer(issuePair($user)))
        ->assertOk()
        ->assertJsonPath('timezone', null);
});

it('applies the account or negotiated locale with the middleware', function (): void {
    Route::middleware(['authentication.locale:users'])->get('/_locale', fn () => app()->getLocale());
    $user = User::factory()->create(['locale' => 'sk']);

    $this->get('/_locale', ['Accept-Language' => 'en'])->assertSee('en');
    $this->get('/_locale', ['Accept-Language' => 'sk'])->assertSee('sk');
    $this->get('/_locale', [...bearer(issuePair($user)), 'Accept-Language' => 'en'])->assertSee('sk');
});
