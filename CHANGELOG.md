# Changelog

All notable changes to this package will be documented in this file.

## Unreleased

- Initial scaffold from `package-template-for-laravel`.
- Fixed `bin/rename-package.sh` on GNU sed: the hardcoded BSD `sed -i ''` form made the
  script exit 2 on the first file, so the template could not rename a package on Linux or
  in CI at all. The sed flavour is now detected, and paths are iterated NUL-delimited.
- Pinned the rename script with `tests/Feature/RenamePackageScriptTest.php`, which runs it
  against a throwaway copy of the tree — the bug above cannot return silently.
- `bin/rename-package.sh` now deletes itself and its self-test as its last act, staging both
  as deletions. The script is the one file its own rewrite cannot reach — its substitution
  patterns are the tokens — so a package that kept it kept `PackageTemplate` /
  `package-template` / `PACKAGE_TEMPLATE` in the tree while the README called keeping it
  harmless. The README and the script's printed steps now say so, and the self-test greps
  every file type instead of the script's own `--include` list, which is the check a
  scaffolded package is actually accepted against.
