<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

/**
 * Merges a guard's own block over `authentication.defaults`.
 *
 * Associative arrays merge recursively; **lists replace wholesale**. That is the whole
 * reason this exists instead of `array_replace_recursive()`, which merges lists by
 * index — `identifier.columns = ['username']` over `['email']` would stay `['username']`
 * by luck, but `['username']` over `['email', 'phone']` would silently become
 * `['username', 'phone']`.
 */
final class ConfigMerger
{
    /**
     * @param  array<array-key, mixed>  $defaults
     * @param  array<array-key, mixed>  $overrides
     * @return array<array-key, mixed>
     */
    public static function merge(array $defaults, array $overrides): array
    {
        $merged = $defaults;

        foreach ($overrides as $key => $value) {
            $base = $merged[$key] ?? null;

            $merged[$key] = is_array($value) && is_array($base) && self::isAssociative($value) && self::isAssociative($base)
                ? self::merge($base, $value)
                : $value;
        }

        return $merged;
    }

    /**
     * @param  array<array-key, mixed>  $value
     */
    private static function isAssociative(array $value): bool
    {
        return $value !== [] && ! array_is_list($value);
    }
}
