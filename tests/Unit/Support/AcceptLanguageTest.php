<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Support\AcceptLanguage;

function negotiate(array $headers, array $supported = ['en', 'sk', 'de-AT']): ?string
{
    $request = Request::create('/', 'GET', server: array_combine(
        array_map(static fn (string $name): string => 'HTTP_'.strtoupper(str_replace('-', '_', $name)), array_keys($headers)),
        array_values($headers),
    ));

    return (new AcceptLanguage)->negotiate($request, guardConfig(['locale' => ['supported' => $supported]]));
}

it('negotiates the best supported locale', function (array $headers, ?string $expected): void {
    expect(negotiate($headers))->toBe($expected);
})->with([
    'exact' => [['Accept-Language' => 'sk'], 'sk'],
    'prefix fallback' => [['Accept-Language' => 'sk-SK'], 'sk'],
    'configured spelling' => [['Accept-Language' => 'de_at'], 'de-AT'],
    'q-values' => [['Accept-Language' => 'fr;q=1, en;q=0.4, sk;q=0.8'], 'sk'],
    'q=0 excluded' => [['Accept-Language' => 'sk;q=0, en;q=0.1'], 'en'],
    'stable for equal q' => [['Accept-Language' => 'en, sk'], 'en'],
    'wildcard' => [['Accept-Language' => 'fr, *;q=0.5'], 'en'],
    'nothing supported' => [['Accept-Language' => 'fr, it'], null],
    'garbage' => [['Accept-Language' => '!!!, <script>'], null],
    'empty header' => [['Accept-Language' => ''], null],
    'explicit header wins' => [['X-Locale' => 'sk', 'Accept-Language' => 'en'], 'sk'],
    'unsupported explicit header falls through' => [['X-Locale' => 'fr', 'Accept-Language' => 'en'], 'en'],
]);

it('bounds the header to 20 entries and 1 KB', function (): void {
    $noise = implode(',', array_fill(0, 25, 'fr'));

    expect(negotiate(['Accept-Language' => $noise.',sk']))->toBeNull()
        ->and(AcceptLanguage::parse(str_repeat('a', 2000).',sk'))->toBe([])
        ->and(AcceptLanguage::parse('en-GB;q=0.9, sk'))->toBe(['sk', 'en-GB']);
});

it('falls back to app.locale when nothing is configured', function (): void {
    expect(guardConfig()->supportedLocales())->toBe(['en']);
});
