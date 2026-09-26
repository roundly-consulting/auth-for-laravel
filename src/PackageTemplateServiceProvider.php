<?php

declare(strict_types=1);

namespace RoundlyConsulting\PackageTemplate;

use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;

final class PackageTemplateServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('package-template')
            ->hasConfigFile()
            ->contributesToAbout(static fn (): array => [
                'Enabled' => config('package-template.enabled', true) ? 'YES' : 'NO',
            ]);

        // Grow this as the package grows:
        //   ->hasMigrations()
        //   ->hasCommands([SomeCommand::class])
        //   ->hasViews() / ->hasTranslations()
        //   ->hasRoutes('package-template.php')
        //   ->hasFacadeAlias(SomeFacade::class)
        // See RoundlyConsulting\PackageToolkit\Package for the full fluent API.
    }

    public function register(): void
    {
        parent::register();

        // Container bindings (bind/singleton/scoped) go here — never in boot().
    }
}
