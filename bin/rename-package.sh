#!/usr/bin/env bash
# Rename this template into a new roundly-consulting *-for-laravel package.
#
# Usage:
#   bash bin/rename-package.sh Credits
#
# The argument is the StudlyCase domain name (no "-for-laravel" suffix). It derives:
#   repo/composer name  credits-for-laravel      (kebab-case + -for-laravel)
#   namespace           RoundlyConsulting\Credits
#   service provider    CreditsServiceProvider
#   config handle/file  config/credits.php, config('credits.*')
#   env var prefix      CREDITS_
#
# Run this once, right after creating a new repo from this template and cloning it.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: bash bin/rename-package.sh <StudlyCaseDomain>" >&2
    exit 1
fi

domain="$1"

if ! [[ "$domain" =~ ^[A-Z][A-Za-z0-9]*$ ]]; then
    echo "Domain must be StudlyCase, e.g. Credits or MediaLibrary (got: $domain)" >&2
    exit 1
fi

# StudlyCase -> kebab-case: insert a dash before an uppercase letter that follows a
# lowercase/digit, then lowercase everything (MediaLibrary -> media-library).
kebab="$(echo "$domain" | sed -E 's/([a-z0-9])([A-Z])/\1-\2/g' | tr '[:upper:]' '[:lower:]')"
upper_snake="$(echo "$kebab" | tr '[:lower:]-' '[:upper:]_')"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "Renaming template -> ${domain} (${kebab}-for-laravel)"

# The two seds disagree about -i: GNU takes no backup suffix, BSD/macOS requires an explicit
# (empty) one. Passing '' to GNU sed makes it read '' as a filename and exit 2, so detect once
# rather than guess -- only GNU sed answers --version.
if sed --version >/dev/null 2>&1; then
    sed_inplace() {
        sed -i "$@"
    }
else
    sed_inplace() {
        sed -i '' "$@"
    }
fi

# -Z/-d '' so a path containing a space survives; a bare `for f in $files` would split it.
grep -rlZE 'PackageTemplate|package-template|PACKAGE_TEMPLATE' \
    --include='*.php' --include='*.json' --include='*.md' --include='*.yml' \
    --include='*.neon' --include='*.dist' \
    --exclude-dir='.git' --exclude-dir='vendor' --exclude-dir='node_modules' . |
    while IFS= read -r -d '' f; do
        sed_inplace \
            -e "s/PackageTemplate/${domain}/g" \
            -e "s/package-template/${kebab}/g" \
            -e "s/PACKAGE_TEMPLATE/${upper_snake}/g" \
            "$f"
    done

git mv src/PackageTemplateServiceProvider.php "src/${domain}ServiceProvider.php"
git mv config/package-template.php "config/${kebab}.php"

# Last act: delete the template's own scaffolding. This script is the one file the rewrite
# above cannot reach -- its substitution patterns ARE the tokens, so it is excluded from its
# own --include list, and leaving it behind leaves PackageTemplate/package-template/
# PACKAGE_TEMPLATE in a package that is supposed to be clean of them. The self-test only
# tests this script, so it goes with it.
#
# -f because git rm refuses a file that differs from HEAD, and the sed pass above just
# rewrote the test file. Both are removals staged against a committed HEAD, so `git restore
# --staged --worktree` brings them back if you need to look at them.
#
# Deleting the running script is safe: bash keeps its own file descriptor, so the rest of
# this file still executes.
git rm -qf bin/rename-package.sh tests/Feature/RenamePackageScriptTest.php

cat <<EOF

Done. Removed the template's own scaffolding, staged as deletions:
  bin/rename-package.sh (this script) and tests/Feature/RenamePackageScriptTest.php.
Commit them with the rest of the rename — keeping either one leaves template tokens or a
test of a script that no longer exists in ${kebab}-for-laravel.

Remaining manual steps:
  1. Rename the repo itself on GitHub (and this local directory) to ${kebab}-for-laravel.
  2. Edit composer.json: write a real "description" and "keywords".
  3. Review README.md and CHANGELOG.md — replace the placeholder text.
  4. composer install, then run the quality gate:
       composer format && composer test && composer analyse && composer audit
  5. Confirm nothing template-shaped survived — this must print nothing:
       grep -rE 'PackageTemplate|package-template|PACKAGE_TEMPLATE' \\
         --exclude-dir=.git --exclude-dir=vendor .
EOF
