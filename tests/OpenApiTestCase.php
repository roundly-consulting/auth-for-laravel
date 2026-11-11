<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests;

use Dedoc\Scramble\ScrambleServiceProvider;
use RoundlyConsulting\Auth\OpenApi\AuthErrorResponses;

/**
 * Boots the test app with an OpenAPI generator, as a host that documents its API would.
 */
abstract class OpenApiTestCase extends TestCase
{
    protected function packageProviders(): array
    {
        return [...parent::packageProviders(), ScrambleServiceProvider::class];
    }

    protected function configBeforeBoot(): array
    {
        return [
            ...parent::configBeforeBoot(),
            'scramble.api_path' => 'users/auth',
            'scramble.extensions' => [AuthErrorResponses::class],
        ];
    }
}
