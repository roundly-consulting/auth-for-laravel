# package-template-for-laravel

A GitHub **template repository** for scaffolding new `roundly-consulting/*-for-laravel`
packages. It is not itself a shippable package — it's a working, green skeleton that
already follows every workspace convention (native service provider on top of
`package-toolkit-for-laravel`, Pest 4 + Testbench via `testing-for-laravel`, Pint,
Larastan level 7, the three GitHub workflows, dependabot) so a new package starts from
day one compliant instead of retrofitted later.

## Requirements

- PHP ^8.4
- Laravel 12.x or 13.x

## Using this template

1. On GitHub, click **"Use this template" → "Create a new repository"** under
   `roundly-consulting`, named `<domain>-for-laravel` (e.g. `credits-for-laravel`). Keep
   it **private**.
2. Clone it into this workspace, next to the other packages:

   ```bash
   gh repo clone roundly-consulting/<domain>-for-laravel ~/Code/Packages/<domain>-for-laravel
   cd ~/Code/Packages/<domain>-for-laravel
   ```

3. Run the rename script with the StudlyCase domain name (no `-for-laravel` suffix):

   ```bash
   bash bin/rename-package.sh Credits
   ```

   This rewrites every `PackageTemplate` / `package-template` / `PACKAGE_TEMPLATE`
   occurrence (namespace, composer name, service provider, config handle, env var prefix,
   GitHub URLs) to the new domain, and renames the two files that carry the name in their
   filename (`src/PackageTemplateServiceProvider.php`, `config/package-template.php`).

   As its last act it deletes the template's own scaffolding — `bin/rename-package.sh` and
   `tests/Feature/RenamePackageScriptTest.php` — and stages both as deletions. Neither may
   survive into the new package: the script's substitution patterns are the one place the
   rewrite cannot reach, so keeping it keeps template tokens, and the self-test tests a
   script that is no longer there. If you restore either one, delete it again before you
   commit.

4. Finish the manual steps the script prints: write a real `composer.json` description,
   rewrite this README and `CHANGELOG.md` for the real package, then run the quality gate:

   ```bash
   composer install
   composer format && composer test && composer analyse && composer audit
   ```

   A scaffolded package is expected to be clean of template tokens — this must print
   nothing:

   ```bash
   grep -rE 'PackageTemplate|package-template|PACKAGE_TEMPLATE' \
     --exclude-dir=.git --exclude-dir=vendor .
   ```

5. Wire the **Tier-0 pairing** — already present in `composer.json`
   (`roundly-consulting/package-toolkit-for-laravel` in `require`,
   `roundly-consulting/testing-for-laravel` in `require-dev`, both path-locally +
   VCS-on-CI). Add any *other* roundly package the new one needs the same way (see the
   `laravel-package-developer` skill's **Cross-package dependencies** section) —
   remember to patch every transitive consumer's `repositories` entry too.
6. Add the `COMPOSER_AUTH_TOKEN` repository secret so CI can install the private VCS deps,
   then manually dispatch the three workflows once and confirm they're green — they run on
   `workflow_dispatch` only, never on push (see the skill's **GitHub Workflows** section).
7. From here, treat it like any other package: run it through the normal
   `laravel-package-improver` → `laravel-package-implementer` → `laravel-package-publisher`
   lifecycle (`/package-pipeline <domain>-for-laravel`) once there's real functionality to
   plan.

## What's included

```
src/
├── Actions/ Commands/ DataTransferObjects/ Events/ Exceptions/ Jobs/ Models/ Traits/
│   (empty — the standard topic folders, ready for real code)
└── PackageTemplateServiceProvider.php   # extends PackageServiceProvider, configures Package
config/package-template.php              # one placeholder key, merged + published + read
database/{factories,migrations}/         # empty — populate as the package grows
tests/
├── TestCase.php           # extends PackageTestCase (testing-for-laravel)
├── Pest.php
├── ArchTest.php           # the arch presets that apply to a model-less, migration-less package
└── ConfigContractTest.php # pins the config file against what src/ actually reads
```

Two more files exist only for the template itself and are deleted by step 3, so they never
reach a real package: `bin/rename-package.sh` and its self-test
`tests/Feature/RenamePackageScriptTest.php`, which runs the script against a throwaway copy
of this tree.

Nothing here is example/demo domain code — it's the tooling and folder shape only. Add
`src/Models`, `src/Actions`, migrations, etc. as the real package needs them, following the
`laravel-package-developer` skill's conventions for each (Models use `$guarded = []` +
`SoftDeletes` + a factory; Actions take DTOs, never arrays; migrations never define
`down()`; and so on).

## Testing

```bash
composer test
```

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
