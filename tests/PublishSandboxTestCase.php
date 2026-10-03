<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\File;

/**
 * `authentication:install` publishes into the host's config/ and database/migrations: here a
 * throwaway directory per test, set before the providers boot (their publish destinations
 * are fixed then) — never the shared testbench skeleton every parallel process loads its
 * configuration from. A config file left there is loaded by every later test as the
 * host's own, overriding the package defaults.
 */
abstract class PublishSandboxTestCase extends TestCase
{
    private string $sandbox = '';

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $this->sandbox = sys_get_temp_dir().'/authentication-publish-'.bin2hex(random_bytes(6));
        File::ensureDirectoryExists($this->sandbox.'/config');
        File::ensureDirectoryExists($this->sandbox.'/database/migrations');

        $app->useConfigPath($this->sandbox.'/config');
        $app->useDatabasePath($this->sandbox.'/database');
    }

    protected function tearDown(): void
    {
        if ($this->sandbox !== '') {
            File::deleteDirectory($this->sandbox);
        }

        parent::tearDown();
    }
}
