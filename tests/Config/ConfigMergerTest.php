<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Guards\ConfigMerger;

it('merges associative arrays recursively', function (): void {
    expect(ConfigMerger::merge(
        ['login' => ['password' => true, 'magic_link' => false], 'ttl' => 5],
        ['login' => ['magic_link' => true]],
    ))->toBe(['login' => ['password' => true, 'magic_link' => true], 'ttl' => 5]);
});

it('replaces lists wholesale instead of merging them by index', function (): void {
    expect(ConfigMerger::merge(
        ['identifier' => ['columns' => ['email', 'phone']]],
        ['identifier' => ['columns' => ['username']]],
    ))->toBe(['identifier' => ['columns' => ['username']]]);
});

it('lets a scalar or null override an array and vice versa', function (): void {
    expect(ConfigMerger::merge(['a' => ['x' => 1], 'b' => 1, 'c' => []], ['a' => null, 'b' => ['y' => 2], 'c' => ['z' => 3]]))
        ->toBe(['a' => null, 'b' => ['y' => 2], 'c' => ['z' => 3]]);
});
