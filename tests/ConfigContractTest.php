<?php

declare(strict_types=1);

/**
 * The config contract, pinned in both directions from day one:
 *
 *  - forward — every key the code reads is shipped. A key the code reads but the file never
 *    ships is a null in every application that did not publish the config.
 *  - reverse — every shipped leaf is read. A key nothing reads is dead config that lies to
 *    the host: it invites somebody to set it, and then nothing happens.
 *
 * Keep both directions green as the package's real keys replace the placeholder one. Reads
 * are token-scraped from `src/` — plus a sibling `database/` and `routes/` when they exist —
 * so a key read from outside that scope (a view, a directory this call does not name) scrapes
 * as unread and is reported exactly like a dead one: widen the scanned directories rather
 * than allow-list it. The call below passes no options; `toSatisfyConfigContract` in
 * testing-for-laravel documents the ones a growing package needs, such as excluding a file
 * that renders keys instead of reading them.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../config/package-template.php')->toSatisfyConfigContract(__DIR__.'/../src');
});
