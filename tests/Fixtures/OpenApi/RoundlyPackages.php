<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\OpenApi;

use Dedoc\Scramble\Infer\Configuration\DefinitionMatcher;

/**
 * Every roundly class, which a host installs under `vendor/`: the generator reads those
 * through reflection (declared types + PHPDoc) and never parses their method bodies.
 */
final readonly class RoundlyPackages implements DefinitionMatcher
{
    public function matches(string $class): bool
    {
        return str_starts_with($class, 'RoundlyConsulting\\') && ! str_starts_with($class, 'RoundlyConsulting\\Auth\\Tests\\');
    }
}
