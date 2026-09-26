<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Contracts\NegotiatesLocale;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Negotiates a supported locale: the guard's locale header (default `X-Locale`) wins,
 * then `Accept-Language` parsed natively — q-values, `*`, at most 20 entries and 1 KB —
 * matched exactly, then by language prefix (`sk-SK` → `sk`).
 */
final class AcceptLanguage implements NegotiatesLocale
{
    public const string TAG_PATTERN = '/^[A-Za-z]{2,3}([_-][A-Za-z0-9]{2,8})*$/';

    private const int MAX_ENTRIES = 20;

    private const int MAX_BYTES = 1024;

    public function negotiate(Request $request, GuardConfig $guard): ?string
    {
        $supported = $guard->supportedLocales();
        $header = $guard->localeHeader();

        if ($header !== null) {
            $explicit = $request->header($header);

            if (is_string($explicit) && ($match = self::match(trim($explicit), $supported)) !== null) {
                return $match;
            }
        }

        $accept = $request->header('Accept-Language');

        if (! is_string($accept) || $accept === '') {
            return null;
        }

        foreach (self::parse($accept) as $tag) {
            if ($tag === '*') {
                return $supported[0] ?? null;
            }

            $match = self::match($tag, $supported);

            if ($match !== null) {
                return $match;
            }
        }

        return null;
    }

    /**
     * The tags of an Accept-Language header, best first (stable for equal q).
     *
     * @return list<string>
     */
    public static function parse(string $header): array
    {
        $entries = [];

        foreach (array_slice(explode(',', substr($header, 0, self::MAX_BYTES)), 0, self::MAX_ENTRIES) as $position => $part) {
            $pieces = explode(';', trim($part));
            $tag = trim($pieces[0]);
            $quality = 1.0;

            foreach (array_slice($pieces, 1) as $parameter) {
                $parameter = trim($parameter);

                if (str_starts_with($parameter, 'q=') && is_numeric(substr($parameter, 2))) {
                    $quality = (float) substr($parameter, 2);
                }
            }

            if ($quality <= 0.0 || ($tag !== '*' && preg_match(self::TAG_PATTERN, $tag) !== 1)) {
                continue;
            }

            $entries[] = ['tag' => $tag, 'q' => $quality, 'position' => $position];
        }

        usort($entries, static fn (array $a, array $b): int => [$b['q'], $a['position']] <=> [$a['q'], $b['position']]);

        return array_map(static fn (array $entry): string => $entry['tag'], $entries);
    }

    /**
     * The supported locale a tag selects (exact, then language prefix), in its
     * configured spelling.
     *
     * @param  list<string>  $supported
     */
    public static function match(string $tag, array $supported): ?string
    {
        if (preg_match(self::TAG_PATTERN, $tag) !== 1) {
            return null;
        }

        $normalized = self::normalize($tag);

        foreach ($supported as $locale) {
            if (self::normalize($locale) === $normalized) {
                return $locale;
            }
        }

        $language = explode('-', $normalized)[0];

        foreach ($supported as $locale) {
            if (self::normalize($locale) === $language) {
                return $locale;
            }
        }

        return null;
    }

    private static function normalize(string $tag): string
    {
        return strtolower(str_replace('_', '-', $tag));
    }
}
