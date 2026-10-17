<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\PHPStan;

use Illuminate\Database\Schema\Blueprint;
use PHPStan\Reflection\ClassReflection;
use PHPStan\Reflection\MethodReflection;
use PHPStan\Reflection\MethodsClassReflectionExtension;
use PHPStan\Type\VoidType;

/**
 * Makes the `$table->authenticationColumns()` schema macro visible to PHPStan. A macro only exists
 * once the provider has booted, which a static analyser cannot count on. A reflection extension
 * rather than a stub because the toolkit already stubs Blueprint and PHPStan honours one stub per
 * class. Loaded into consumers through `extra.phpstan.includes` (phpstan/extension-installer);
 * only PHPStan ever loads this namespace, so `phpstan/phpstan` stays a dev dependency.
 */
final class AuthenticationMacrosExtension implements MethodsClassReflectionExtension
{
    public const array BLUEPRINT = ['authenticationColumns'];

    public function hasMethod(ClassReflection $classReflection, string $methodName): bool
    {
        return in_array($methodName, self::BLUEPRINT, true) && $classReflection->is(Blueprint::class);
    }

    public function getMethod(ClassReflection $classReflection, string $methodName): MethodReflection
    {
        return new MacroMethodReflection($classReflection, $methodName, new VoidType);
    }
}
