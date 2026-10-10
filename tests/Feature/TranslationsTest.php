<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\File;

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
        ->and(trans('authentication::notifications.magic_link.subject', ['app' => 'Roundly']))->toBe('Váš prihlasovací odkaz do aplikácie Roundly')
        ->and(trans('authentication::notifications.password_changed.by_actor.subject', ['app' => 'Roundly']))->toBe('Vaše heslo do aplikácie Roundly zmenil administrátor');

    app()->setLocale('en');

    expect(trans('authentication::messages.errors.invalid_credentials'))->toBe('These credentials do not match our records.')
        ->and(trans('authentication::notifications.magic_link.subject', ['app' => 'Roundly']))->toBe('Your sign-in link for Roundly');
});

it('keeps the administrator copy for a host that published the translations before it existed', function (): void {
    $dir = sys_get_temp_dir().'/authentication-lang-'.getmypid().'-'.bin2hex(random_bytes(4));
    File::ensureDirectoryExists($dir.'/vendor/authentication/en');
    File::put($dir.'/vendor/authentication/en/notifications.php', "<?php return ['password_changed' => ['subject' => 'Our own subject']];");

    try {
        app('translator')->getLoader()->addPath($dir);

        expect(trans('authentication::notifications.password_changed.subject'))->toBe('Our own subject')
            ->and(trans('authentication::notifications.password_changed.by_actor.subject', ['app' => 'Roundly']))->toBe('Your Roundly password was changed by an administrator');
    } finally {
        File::deleteDirectory($dir);
    }
});
