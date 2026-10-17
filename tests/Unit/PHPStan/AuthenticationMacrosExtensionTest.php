<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;
use PHPStan\Reflection\ParameterReflection;
use PHPStan\Testing\PHPStanTestCase;
use PHPStan\TrinaryLogic;
use PHPStan\Type\VerbosityLevel;
use RoundlyConsulting\Auth\PHPStan\AuthenticationMacrosExtension;

/**
 * A macro only exists once the provider has booted, which a static analyser cannot count on. These
 * cases pin the reflection extension that declares it anyway — against the macro the provider
 * really registers and against the composer wiring consumers auto-load it through. The fixture
 * migration in tests/PHPStan is analysed by `composer analyse` on top.
 */
$root = dirname(__DIR__, 3);

/** The signature PHPStan sees: "name: type" per parameter, then "): return". */
$static = static function (string $macro): array {
    $blueprint = PHPStanTestCase::createReflectionProvider()->getClass(Blueprint::class);
    $variant = (new AuthenticationMacrosExtension)->getMethod($blueprint, $macro)->getVariants()[0];

    return [
        ...array_map(static fn (ParameterReflection $parameter): string => $parameter->getName().': '.$parameter->getType()->describe(VerbosityLevel::precise()), $variant->getParameters()),
        '): '.$variant->getReturnType()->describe(VerbosityLevel::precise()),
    ];
};

/** The signature of the closure the booted provider registered, in the same shape. */
$runtime = static function (string $macro): array {
    /** @var array<string, Closure> $macros */
    $macros = (new ReflectionProperty(Blueprint::class, 'macros'))->getValue();
    $function = new ReflectionFunction($macros[$macro]);

    return [
        ...array_map(static fn (ReflectionParameter $parameter): string => $parameter->getName().': '.$parameter->getType(), $function->getParameters()),
        '): '.$function->getReturnType(),
    ];
};

it('declares exactly the macros the provider registers', function () use ($root): void {
    preg_match_all("/Blueprint::macro\\('(\\w+)'/", (string) file_get_contents($root.'/src/AuthenticationServiceProvider.php'), $matches);

    $extension = new AuthenticationMacrosExtension;
    $blueprint = PHPStanTestCase::createReflectionProvider()->getClass(Blueprint::class);

    expect($matches[1])->toBe(AuthenticationMacrosExtension::BLUEPRINT);

    foreach (AuthenticationMacrosExtension::BLUEPRINT as $macro) {
        expect(Blueprint::hasMacro($macro))->toBeTrue()
            ->and($extension->hasMethod($blueprint, $macro))->toBeTrue();
    }
});

it('declares the macro on Blueprint only', function (): void {
    $extension = new AuthenticationMacrosExtension;
    $provider = PHPStanTestCase::createReflectionProvider();

    expect($extension->hasMethod($provider->getClass(Blueprint::class), 'dropColumn'))->toBeFalse()
        ->and($extension->hasMethod($provider->getClass(ColumnDefinition::class), 'authenticationColumns'))->toBeFalse();
});

it('matches the registered macro signature exactly', function (string $macro) use ($static, $runtime): void {
    expect($static($macro))->toBe(['): void'])
        ->and($static($macro))->toBe($runtime($macro));
})->with(['authenticationColumns']);

it('describes a public, non-static, side-effecting method', function (): void {
    $blueprint = PHPStanTestCase::createReflectionProvider()->getClass(Blueprint::class);
    $method = (new AuthenticationMacrosExtension)->getMethod($blueprint, 'authenticationColumns');

    expect($method->getName())->toBe('authenticationColumns')
        ->and($method->getDeclaringClass()->getName())->toBe(Blueprint::class)
        ->and($method->getPrototype())->toBe($method)
        ->and($method->isPublic())->toBeTrue()
        ->and($method->isPrivate())->toBeFalse()
        ->and($method->isStatic())->toBeFalse()
        ->and($method->getDocComment())->toBeNull()
        ->and($method->getThrowType())->toBeNull()
        ->and($method->getDeprecatedDescription())->toBeNull()
        ->and($method->isDeprecated())->toEqual(TrinaryLogic::createNo())
        ->and($method->isFinal())->toEqual(TrinaryLogic::createNo())
        ->and($method->isInternal())->toEqual(TrinaryLogic::createNo())
        ->and($method->hasSideEffects())->toEqual(TrinaryLogic::createYes())
        ->and($method->getVariants())->toHaveCount(1);
});

it('is wired into composer and extension.neon for consumers, and analysed here', function () use ($root): void {
    $composer = json_decode((string) file_get_contents($root.'/composer.json'), true, flags: JSON_THROW_ON_ERROR);

    expect($composer['extra']['phpstan']['includes'] ?? [])->toBe(['extension.neon'])
        ->and((string) file_get_contents($root.'/extension.neon'))
        ->toContain(AuthenticationMacrosExtension::class)
        ->toContain('phpstan.broker.methodsClassReflectionExtension')
        ->and((string) file_get_contents($root.'/phpstan.neon.dist'))
        ->toContain('- extension.neon')
        ->toContain('- tests/PHPStan');
});

it('keeps PHPStan out of the runtime: only src/PHPStan names it', function () use ($root): void {
    $scanned = 0;

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root.'/src', FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php' || str_starts_with($file->getPathname(), $root.'/src/PHPStan/')) {
            continue;
        }

        $code = '';

        foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
            if (! is_array($token) || ! in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                $code .= is_array($token) ? $token[1] : $token;
            }
        }

        $scanned++;
        expect(str_contains($code, 'PHPStan\\'))->toBeFalse($file->getPathname());
    }

    expect($scanned)->toBeGreaterThan(10);
});

it('lets the extension import only PHPStan and the schema classes', function () use ($root): void {
    $imports = [];

    foreach (glob($root.'/src/PHPStan/*.php') ?: [] as $file) {
        preg_match_all('/^use ([^;]+);/m', (string) file_get_contents($file), $matches);
        $imports = [...$imports, ...$matches[1]];
    }

    expect($imports)->not->toBeEmpty();

    foreach ($imports as $import) {
        expect(str_starts_with($import, 'PHPStan\\') || str_starts_with($import, 'Illuminate\\Database\\Schema\\'))->toBeTrue($import);
    }
});
