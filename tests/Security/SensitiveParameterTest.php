<?php

declare(strict_types=1);

/**
 * Every parameter that can carry a secret is `#[SensitiveParameter]`, so it never lands
 * in a stack trace or a log. Non-vacuous: the sweep must find at least 25 of them.
 */
it('marks every secret-carrying parameter sensitive', function (): void {
    $names = ['password', 'currentPassword', 'newPassword', 'token', 'code', 'refreshToken', 'challengeToken', 'secret', 'provisioningUri', 'tokenOrCode', 'accessReference'];
    $found = 0;
    $missing = [];

    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) realpath(__DIR__.'/../../src'), FilesystemIterator::SKIP_DOTS));

    foreach ($iterator as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $relative = substr($file->getPathname(), strlen((string) realpath(__DIR__.'/../../src')) + 1);
        $class = 'RoundlyConsulting\Auth\\'.str_replace(['/', '.php'], ['\\', ''], $relative);

        if (! class_exists($class) && ! trait_exists($class) && ! interface_exists($class)) {
            continue;
        }

        foreach ((new ReflectionClass($class))->getMethods() as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            foreach ($method->getParameters() as $parameter) {
                if (! in_array($parameter->getName(), $names, true) || ! in_array((string) $parameter->getType(), ['string', '?string'], true)) {
                    continue;
                }

                $found++;

                if ($parameter->getAttributes(SensitiveParameter::class) === []) {
                    $missing[] = "{$class}::{$method->getName()}(\${$parameter->getName()})";
                }
            }
        }
    }

    expect($missing)->toBe([])->and($found)->toBeGreaterThanOrEqual(25);
});
