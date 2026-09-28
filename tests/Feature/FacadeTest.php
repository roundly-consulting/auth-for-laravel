<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Facades\Authentication;

/*
 * No `toBeFakeable()`: the package ships no `Authentication::fake()` on purpose — every
 * write already fires a domain event (assert with `Event::fake()`), and the
 * `InteractsWithAuthentication` helpers issue REAL tokens so tests exercise the guard,
 * audience, denylist and token-version checks a stub would hide.
 */
it('documents its root and reaches every host-facing action', function (): void {
    expect(Authentication::class)
        ->toDocumentItsRoot()
        ->toReachEveryAction(__DIR__.'/../../src/Actions');
});
