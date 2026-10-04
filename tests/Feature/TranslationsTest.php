<?php

declare(strict_types=1);

use Illuminate\Support\Arr;

dataset('translation files', ['messages', 'notifications', 'validation']);

/**
 * @return array<string, mixed>
 */
function translationLines(string $locale, string $file): array
{
    return Arr::dot(require __DIR__.'/../../resources/lang/'.$locale.'/'.$file.'.php');
}

/**
 * @return list<string>
 */
function translationPlaceholders(mixed $line): array
{
    preg_match_all('/:([A-Za-z_]+)/', (string) $line, $matches);

    $names = array_values(array_unique($matches[1]));
    sort($names);

    return $names;
}

it('ships the same keys in every language', function (string $file): void {
    $en = translationLines('en', $file);
    $sk = translationLines('sk', $file);

    expect($en)->not->toBeEmpty()
        ->and(array_keys($sk))->toBe(array_keys($en));
})->with('translation files');

it('keeps every placeholder in every language', function (string $file): void {
    $sk = translationLines('sk', $file);

    foreach (translationLines('en', $file) as $key => $line) {
        expect(translationPlaceholders($sk[$key] ?? null))->toBe(translationPlaceholders($line), "{$file}.{$key}");
    }
})->with('translation files');

it('loads the slovak lines through the package namespace', function (): void {
    app()->setLocale('sk');

    expect(trans('authentication::messages.errors.invalid_credentials'))->toBe('Tieto prihlasovacie údaje sa nezhodujú s našimi záznamami.')
        ->and(trans('authentication::notifications.magic_link.subject', ['app' => 'Roundly']))->toBe('Váš prihlasovací odkaz do aplikácie Roundly');

    app()->setLocale('en');

    expect(trans('authentication::messages.errors.invalid_credentials'))->toBe('These credentials do not match our records.')
        ->and(trans('authentication::notifications.magic_link.subject', ['app' => 'Roundly']))->toBe('Your sign-in link for Roundly');
});
