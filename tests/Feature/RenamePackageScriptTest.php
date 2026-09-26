<?php

declare(strict_types=1);

/**
 * `bin/rename-package.sh` is the one piece of this repository that cannot be proven by
 * reading it: it is shell, it shells out to `sed` and `git mv`, and the two seds disagree
 * about `-i`. The BSD form `sed -i ''` was shipped here for real — GNU sed reads the empty
 * argument as a filename and exits 2, and under `set -euo pipefail` that aborted the run on
 * the first file, leaving a half-renamed tree. Every agent run and CI runner is Linux, so
 * the template could not rename a package at all while a comment claimed it could.
 *
 * These tests therefore RUN the script against a throwaway copy of the real tree and assert
 * on the result. A grep for the offending string would pin the one spelling we happen to
 * know about; executing it pins the behaviour, on whichever sed the runner actually has.
 *
 * They also pin the acceptance criterion a scaffolded package is checked against — no
 * PackageTemplate/package-template/PACKAGE_TEMPLATE anywhere, in ANY file type. That is
 * why the script deletes itself and this file at the end: the script's own substitution
 * patterns are the one place its rewrite cannot reach.
 *
 * This file only ever runs in the template. In a renamed package it is gone, along with
 * the script it tests.
 */

/**
 * Copy every tracked file into a scratch git repository and return its path.
 *
 * Tracked files only — `git ls-files` skips vendor/ and node_modules/, which the script
 * excludes anyway and which would make the copy enormous. The copy is `git init`ed and
 * committed because the script finishes with `git mv` and `git rm` calls: `git mv` refuses
 * a path that is not in the index, and `git rm` behaves differently against a repository
 * with no HEAD than against the fresh clone a real user runs this in.
 */
function scratchTemplate(): string
{
    $source = dirname(__DIR__, 2);
    $target = sys_get_temp_dir().'/rename-package-'.bin2hex(random_bytes(6));

    mkdir($target, 0o777, true);

    exec(sprintf('git -C %s ls-files -z', escapeshellarg($source)), $_, $listed);
    expect($listed)->toBe(0, 'could not list the tracked files of the template');

    $files = array_filter(explode("\0", (string) shell_exec(
        sprintf('git -C %s ls-files -z', escapeshellarg($source))
    )));

    foreach ($files as $file) {
        $destination = $target.'/'.$file;

        if (! is_dir(dirname($destination))) {
            mkdir(dirname($destination), 0o777, true);
        }

        copy($source.'/'.$file, $destination);
    }

    // The identity is passed with -c rather than assumed: a CI runner has no global one.
    exec(sprintf(
        'git -C %1$s init -q && git -C %1$s add -A && '
        .'git -C %1$s -c user.name=Test -c user.email=test@example.com -c commit.gpgsign=false '
        .'commit -qm scaffold 2>&1',
        escapeshellarg($target)
    ), $_, $initialised);
    expect($initialised)->toBe(0, 'could not initialise the scratch repository');

    return $target;
}

/**
 * Run the rename script inside the scratch copy.
 *
 * @return array{0: int, 1: string} exit code and combined output
 */
function runRename(string $directory, string $domain): array
{
    exec(sprintf(
        'bash %s %s 2>&1',
        escapeshellarg($directory.'/bin/rename-package.sh'),
        escapeshellarg($domain)
    ), $output, $exitCode);

    return [$exitCode, implode("\n", $output)];
}

/**
 * Files still carrying a template token — every file type, not the script's own filter.
 *
 * This is deliberately the acceptance grep a scaffolded package is judged by, verbatim.
 * Filtering by the script's --include list would grade the rewrite against its own opinion
 * of which files matter and would have called a package clean while `bin/rename-package.sh`
 * still sat in it full of tokens.
 */
function leftoverTemplateTokens(string $directory): string
{
    return (string) shell_exec(sprintf(
        'grep -rlE %s --exclude-dir=.git --exclude-dir=vendor %s 2>/dev/null',
        escapeshellarg('PackageTemplate|package-template|PACKAGE_TEMPLATE'),
        escapeshellarg($directory)
    ));
}

/** Paths the run staged as deletions. */
function stagedDeletions(string $directory): string
{
    return (string) shell_exec(sprintf(
        'git -C %s diff --cached --name-only --diff-filter=D',
        escapeshellarg($directory)
    ));
}

it('renames the whole template on this runner\'s sed', function (): void {
    $directory = scratchTemplate();

    [$exitCode, $output] = runRename($directory, 'Inspire');

    // The regression that shipped: GNU sed exits 2 on `sed -i ''` and pipefail kills the run.
    expect($exitCode)->toBe(0, "the rename script failed:\n".$output);

    // Every file type, so this is the same check a scaffolded package is accepted against.
    expect(leftoverTemplateTokens($directory))
        ->toBe('', 'the rename left template tokens behind');
});

it('deletes the template scaffolding that no rewrite could clean', function (): void {
    $directory = scratchTemplate();

    [$exitCode, $output] = runRename($directory, 'Inspire');
    expect($exitCode)->toBe(0, "the rename script failed:\n".$output);

    // The script's substitution patterns are themselves template tokens, so it cannot
    // rewrite itself out of the tree — it has to leave it. The self-test goes with it:
    // it tests a script the package no longer has.
    expect($directory.'/bin/rename-package.sh')->not->toBeFile()
        ->and($directory.'/tests/Feature/RenamePackageScriptTest.php')->not->toBeFile();

    // Staged, not merely unlinked, so the deletions travel with the rename commit.
    expect(stagedDeletions($directory))
        ->toContain('bin/rename-package.sh')
        ->toContain('tests/Feature/RenamePackageScriptTest.php');

    // Deleting the script mid-run must not truncate it: the closing instructions are
    // printed after the `git rm`, so seeing them proves bash read on past its own removal.
    expect($output)->toContain('Remaining manual steps');
});

it('renames the two files that carry the name in their filename', function (): void {
    $directory = scratchTemplate();

    [$exitCode] = runRename($directory, 'Inspire');
    expect($exitCode)->toBe(0);

    // The `git mv` calls are the last thing the script does, so these existing is also
    // the proof that it ran to completion rather than dying part way.
    expect($directory.'/src/InspireServiceProvider.php')->toBeFile()
        ->and($directory.'/config/inspire.php')->toBeFile()
        ->and($directory.'/src/PackageTemplateServiceProvider.php')->not->toBeFile()
        ->and($directory.'/config/package-template.php')->not->toBeFile();
});

it('rewrites the namespace, composer name and env prefix', function (): void {
    $directory = scratchTemplate();

    [$exitCode] = runRename($directory, 'Inspire');
    expect($exitCode)->toBe(0);

    expect(file_get_contents($directory.'/src/InspireServiceProvider.php'))
        ->toContain('namespace RoundlyConsulting\Inspire;')
        ->toContain('class InspireServiceProvider');

    expect(file_get_contents($directory.'/composer.json'))
        ->toContain('roundly-consulting/inspire-for-laravel');

    expect(file_get_contents($directory.'/config/inspire.php'))
        ->toContain('INSPIRE_');
});

it('derives kebab-case from a multi-word StudlyCase domain', function (): void {
    $directory = scratchTemplate();

    // MediaLibrary is the case the naive `strtolower` would get wrong (medialibrary).
    [$exitCode] = runRename($directory, 'MediaLibrary');
    expect($exitCode)->toBe(0);

    expect($directory.'/config/media-library.php')->toBeFile()
        ->and($directory.'/src/MediaLibraryServiceProvider.php')->toBeFile();

    expect(file_get_contents($directory.'/composer.json'))
        ->toContain('roundly-consulting/media-library-for-laravel');

    expect(file_get_contents($directory.'/config/media-library.php'))
        ->toContain('MEDIA_LIBRARY_');
});

it('rejects a domain that is not StudlyCase', function (string $domain): void {
    $directory = scratchTemplate();

    [$exitCode, $output] = runRename($directory, $domain);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('StudlyCase');

    // A rejected run must not have touched anything — including deleting the script that
    // the user is about to re-run with a corrected argument.
    expect($directory.'/src/PackageTemplateServiceProvider.php')->toBeFile()
        ->and($directory.'/bin/rename-package.sh')->toBeFile();
})->with(['credits', 'media-library', '1Credits', 'Media Library']);
