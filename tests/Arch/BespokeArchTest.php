<?php

declare(strict_types=1);

use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Http\FormRequest;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Jobs\DeliverAuthenticationNotification;
use RoundlyConsulting\Enums\Helpers;

/**
 * The package-specific rules, each pinned with its reason.
 *
 * @return list<string>
 */
function sourceFiles(string $subdirectory = ''): array
{
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) realpath(__DIR__.'/../../src/'.$subdirectory), FilesystemIterator::SKIP_DOTS));
    $files = [];

    foreach ($iterator as $file) {
        if ($file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }

    sort($files);

    return $files;
}

function code(string $file): string
{
    // Source without comments, so a docblock mentioning a symbol is not a hit.
    $code = '';

    foreach (token_get_all((string) file_get_contents($file)) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }

        $code .= is_array($token) ? $token[1] : $token;
    }

    return $code;
}

it('keeps qr-for-laravel behind one adapter (a qr API change touches one file)', function (): void {
    $importers = array_values(array_filter(sourceFiles(), static fn (string $file): bool => str_contains(code($file), 'RoundlyConsulting\Qr\\')));

    expect(array_map('basename', $importers))->toBe(['QrCodeRenderer.php']);
});

it('never builds an otpauth URI itself (two-factor owns the one URI builder)', function (): void {
    foreach (sourceFiles() as $file) {
        expect(code($file))->not->toContain('ProvisioningUri');
    }
});

it('checks passwords in exactly one place', function (): void {
    $checkers = array_values(array_filter(sourceFiles(), static fn (string $file): bool => str_contains(code($file), 'Hash::check(')));

    expect(array_map('basename', $checkers))->toBe(['VerifyPassword.php']);
});

it('never queues a notification directly — only through the encrypted job', function (): void {
    foreach (sourceFiles('Notifications') as $file) {
        expect(code($file))->not->toContain('ShouldQueue');
    }

    expect(is_subclass_of(DeliverAuthenticationNotification::class, ShouldBeEncrypted::class))->toBeTrue()
        ->and(is_subclass_of(DeliverAuthenticationNotification::class, ShouldQueue::class))->toBeTrue();
});

it('never interpolates an authentication config key (the contract could not see it)', function (): void {
    foreach (sourceFiles() as $file) {
        expect(preg_match('/config\(\s*"authentication\.[^"]*\{\$/', code($file)))->toBe(0, basename($file))
            ->and(preg_match("/config\(\s*'authentication\.[^']*'\s*\./", code($file)))->toBe(0, basename($file));
    }
});

it('imports no foreign auth, qr, webauthn, jwt or http vendor', function (): void {
    foreach (sourceFiles() as $file) {
        foreach (['Laravel\Sanctum', 'Laravel\Fortify', 'Illuminate\Auth\Passwords', 'PragmaRX', 'BaconQrCode', 'Webauthn', 'Firebase', 'Lcobucci', 'Jenssegers', 'GuzzleHttp'] as $vendor) {
            expect(code($file))->not->toContain("use {$vendor}");
        }
    }
});

it('uses neither Str::random nor the DB facade', function (): void {
    foreach (sourceFiles() as $file) {
        expect(code($file))->not->toContain('Str::random')->not->toContain('Facades\DB');
    }
});

it('keeps controllers final and invokable, and requests typed', function (): void {
    foreach (sourceFiles('Http/Controllers') as $file) {
        $class = 'RoundlyConsulting\Auth\Http\Controllers\\'.str_replace(['/', '.php'], ['\\', ''], substr($file, strlen(realpath(__DIR__.'/../../src/Http/Controllers')) + 1));
        $reflection = new ReflectionClass($class);
        $public = array_map(static fn (ReflectionMethod $method): string => $method->getName(), $reflection->getMethods(ReflectionMethod::IS_PUBLIC));

        expect($reflection->isFinal())->toBeTrue($class)->and($public)->toBe(['__invoke']);
    }

    foreach (sourceFiles('Http/Requests') as $file) {
        $name = basename($file, '.php');

        if (str_contains($file, 'Concerns') || $name === 'AuthenticationRequest') {
            continue;
        }

        $reflection = new ReflectionClass('RoundlyConsulting\Auth\Http\Requests\\'.$name);

        expect($reflection->isSubclassOf(FormRequest::class))->toBeTrue($name)
            ->and($reflection->hasMethod('toData'))->toBeTrue($name);
    }
});

it('keeps DTOs and events final readonly, enums on Helpers and exceptions on the base', function (): void {
    foreach (['DataTransferObjects', 'Events'] as $namespace) {
        foreach (sourceFiles($namespace) as $file) {
            $reflection = new ReflectionClass("RoundlyConsulting\\Auth\\{$namespace}\\".basename($file, '.php'));

            expect($reflection->isFinal() && $reflection->isReadOnly())->toBeTrue($reflection->getName());
        }
    }

    foreach (sourceFiles('Enums') as $file) {
        expect(class_uses('RoundlyConsulting\Auth\Enums\\'.basename($file, '.php')))->toContain(Helpers::class);
    }

    foreach (sourceFiles('Exceptions') as $file) {
        $class = 'RoundlyConsulting\Auth\Exceptions\\'.basename($file, '.php');

        expect($class === AuthException::class || is_subclass_of($class, AuthException::class))->toBeTrue($class);
    }
});

it('claims single-use state with conditional updates, never a read-then-save', function (): void {
    foreach (['Actions/Challenges/FinalizeChallenge.php', 'Actions/Challenges/RecordChallengeFailure.php', 'Actions/OneTimeTokens/ConsumeOneTimeToken.php', 'Actions/OneTimeTokens/VerifyOneTimeCode.php', 'Actions/Invitations/AcceptInvitation.php'] as $file) {
        expect(code(__DIR__.'/../../src/'.$file))->not->toContain('->save(')->not->toContain('->forceFill(');
    }
});

it('imports no crypto class marked @internal', function (): void {
    $internal = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../../vendor/roundly-consulting/crypto-for-laravel/src', FilesystemIterator::SKIP_DOTS)) as $file) {
        $source = (string) file_get_contents($file->getPathname());

        if ($file->getExtension() === 'php' && preg_match('/\*\s+@internal\b[^\n]*\n(?:\s*\*[^\n]*\n)*\s*\*\/\s*(?:final\s+|abstract\s+|readonly\s+)*(?:class|trait|interface|enum)\s+(\w+)/', $source, $match) === 1
            && preg_match('/namespace\s+([^;]+);/', $source, $namespace) === 1) {
            $internal[] = $namespace[1].'\\'.$match[1];
        }
    }

    foreach (sourceFiles() as $file) {
        foreach ($internal as $class) {
            expect(str_contains(code($file), 'use '.$class.';'))->toBeFalse(basename($file).' imports '.$class);
        }
    }
});
