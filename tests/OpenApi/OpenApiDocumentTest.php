<?php

declare(strict_types=1);

use Dedoc\Scramble\Diagnostics\AbstractDiagnostic;
use Dedoc\Scramble\Diagnostics\ClassContext;
use Dedoc\Scramble\Generator;
use Dedoc\Scramble\Infer\Context;
use Dedoc\Scramble\Scramble;
use Dedoc\Scramble\Support\Helpers\JsonResourceHelper;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Http\Resources\AccountResource;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;
use RoundlyConsulting\Auth\Tests\Fixtures\OpenApi\RoundlyPackages;

/*
 * Hosts generate their API types from the OpenAPI document dedoc/scramble exports. A host
 * installs the package under vendor/, where the generator reads package classes through
 * reflection only (declared types + PHPDoc) and parses just the route actions and resources.
 * "installed" reproduces that; "from source" is a path-repository checkout, parsed in full.
 */

/**
 * @return array{json: string, spec: array<string, mixed>, diagnostics: list<string>}
 */
function exportOpenApi(bool $installed): array
{
    // The generator keeps process-wide state across app instances; start each export clean.
    Context::reset();
    JsonResourceHelper::$jsonResourcesModelTypesCache = [];

    if ($installed) {
        Scramble::infer()->configure()->buildDefinitionsUsingReflectionFor([new RoundlyPackages]);
    }

    $config = Scramble::getGeneratorConfig('default');
    $result = app(Generator::class)->generate($config);

    $json = (string) json_encode($result->spec($config->openApiVersion()), JSON_UNESCAPED_SLASHES);

    return [
        'json' => $json,
        'spec' => json_decode($json, true),
        'diagnostics' => $result->diagnostics()
            ->map(static fn (AbstractDiagnostic $diagnostic): string => $diagnostic->code().' '.($diagnostic->context() instanceof ClassContext ? $diagnostic->context()->class : ''))
            ->values()
            ->all(),
    ];
}

/**
 * The JSON schema of one documented response, through a `#/components/responses` reference.
 *
 * @param  array<string, mixed>  $spec
 * @return array<string, mixed>
 */
function responseSchema(array $spec, string $method, string $path, int|string $status): array
{
    $response = $spec['paths'][$path][$method]['responses'][(string) $status]
        ?? throw new RuntimeException("{$method} {$path} documents no {$status} response");

    if (isset($response['$ref'])) {
        $response = $spec['components']['responses'][basename($response['$ref'])];
    }

    return $response['content']['application/json']['schema'] ?? [];
}

/**
 * @param  array<string, mixed>  $spec
 * @return array<string, mixed>
 */
function schemaComponent(array $spec, string $name): array
{
    return $spec['components']['schemas'][$name] ?? throw new RuntimeException("no {$name} schema");
}

/**
 * @param  array<string, mixed>  $schema
 * @return list<string>
 */
function schemaRefs(array $schema): array
{
    $refs = array_map(static fn (array $item): string => basename($item['$ref'] ?? 'inline'), $schema['anyOf'] ?? [$schema]);
    sort($refs);

    return $refs;
}

/**
 * @param  array<string, mixed>  $schema
 * @return array<string, string|list<string>>
 */
function propertyTypes(array $schema): array
{
    return array_map(static fn (array $property): string|array => $property['type'] ?? 'untyped', $schema['properties'] ?? []);
}

$modes = ['installed under vendor/' => [true], 'parsed from source' => [false]];

$tokensOrChallenge = [
    '/login', '/login/magic-link/consume', '/login/otp/verify', '/login/passkey',
    '/challenge/two-factor', '/challenge/two-factor/enrol/confirm', '/challenge/passkey', '/challenge/passkey/enrol',
];

it('documents every login step as the token pair or the challenge', function (bool $installed) use ($tokensOrChallenge): void {
    $spec = exportOpenApi($installed)['spec'];

    foreach ($tokensOrChallenge as $path) {
        expect(schemaRefs(responseSchema($spec, 'post', $path, 200)))->toBe(['ChallengeResource', 'TokenPairResource'], $path);
    }

    foreach (['/register', '/invitations/accept', '/password/reset'] as $path) {
        expect(schemaRefs(responseSchema($spec, 'post', $path, 200)))->toContain('ChallengeResource', 'TokenPairResource');
    }

    expect(schemaRefs(responseSchema($spec, 'post', '/refresh', 200)))->toBe(['TokenPairResource']);
})->with($modes);

it('types every token pair field', function (bool $installed): void {
    $tokens = schemaComponent(exportOpenApi($installed)['spec'], 'TokenPairResource');

    expect(propertyTypes($tokens))->toBe([
        'status' => 'string',
        'token_type' => 'string',
        'access_token' => 'string',
        'expires_in' => 'integer',
        'expires_at' => 'string',
        'refresh_token' => 'string',
        'refresh_expires_at' => 'string',
        'session_id' => 'string',
    ])
        ->and($tokens['properties']['status']['const'])->toBe('authenticated')
        ->and($tokens['required'])->toHaveCount(8);
})->with($modes);

it('types every challenge field', function (bool $installed): void {
    $challenge = schemaComponent(exportOpenApi($installed)['spec'], 'ChallengeResource');

    expect(propertyTypes($challenge))->toBe([
        'status' => 'string',
        'challenge_token' => 'string',
        'expires_at' => 'string',
        'attempts_left' => 'integer',
        'method' => 'string',
        'completed' => 'array',
        'remaining' => 'array',
    ])
        ->and($challenge['properties']['status']['const'])->toBe('challenge')
        ->and($challenge['properties']['method']['enum'])->toBe(LoginMethod::values()->all())
        ->and($challenge['required'])->toHaveCount(7);
})->with($modes);

it('types the challenge steps with the enum values the package sends', function (): void {
    // From the PHPDoc of PendingChallenge's step helpers, which the generator reads for an
    // installed package (a parsed checkout infers their array_map bodies instead).
    $properties = schemaComponent(exportOpenApi(true)['spec'], 'ChallengeResource')['properties'];
    $remaining = $properties['remaining']['items'];

    expect($properties['completed']['items']['enum'])->toBe(ChallengeStep::values()->all())
        ->and($remaining['required'])->toBe(['step', 'methods'])
        ->and($remaining['properties']['step']['enum'])->toBe(ChallengeStep::values()->all())
        ->and($remaining['properties']['methods']['items']['enum'])->toBe(FactorMethod::values()->all());
});

it('documents me as the default account resource', function (bool $installed): void {
    $spec = exportOpenApi($installed)['spec'];

    expect(schemaRefs(responseSchema($spec, 'get', '/me', 200)['properties']['data']))->toBe(['AccountResource'])
        ->and(propertyTypes(schemaComponent($spec, 'AccountResource')))->toBe([
            'id' => 'untyped',
            'email' => ['string', 'null'],
            'email_verified' => 'boolean',
            'locale' => ['string', 'null'],
            'timezone' => ['string', 'null'],
        ]);
})->with($modes);

it('documents the 202 acknowledgements', function (bool $installed): void {
    $spec = exportOpenApi($installed)['spec'];

    foreach (['/login/magic-link', '/login/otp', '/password/forgot', '/email/verification', '/email/verification/resend', '/email/change', '/reauthenticate/otp'] as $path) {
        expect(responseSchema($spec, 'post', $path, 202)['properties']['status']['const'] ?? null)->toBe('sent', $path);
    }

    foreach (['/register', '/invitations/accept'] as $path) {
        expect(responseSchema($spec, 'post', $path, 202)['properties']['status']['type'] ?? null)->toBe('string', $path);
    }
})->with($modes);

it('types the credential-change bodies with the optional re-issued pair', function (bool $installed): void {
    $spec = exportOpenApi($installed)['spec'];

    foreach ([['put', '/password', 'changed'], ['post', '/two-factor/confirm', 'enabled'], ['delete', '/two-factor', 'disabled'], ['delete', '/passkeys/{passkey}', 'removed']] as [$method, $path, $status]) {
        $schema = responseSchema($spec, $method, $path, 200);

        expect($schema['properties']['status']['const'])->toBe($status, $path)
            ->and(schemaRefs($schema['properties']['tokens']))->toBe(['TokenPairResource', 'inline'], $path);
    }

    expect(propertyTypes(schemaComponent($spec, 'RecoveryCodesResource')))->toBe(['recovery_codes' => 'array', 'tokens' => 'untyped'])
        ->and(schemaRefs(responseSchema($spec, 'post', '/passkeys', 201)['properties']['passkey']))->toBe(['PasskeyResource']);
})->with($modes);

it('types every list item, with pagination where the list pages', function (bool $installed): void {
    $spec = exportOpenApi($installed)['spec'];

    foreach (['/sessions' => 'SessionResource', '/activity' => 'LoginActivityResource', '/invitations' => 'InvitationResource', '/passkeys' => 'PasskeyResource'] as $path => $resource) {
        expect(schemaRefs(responseSchema($spec, 'get', $path, 200)['properties']['data']['items']))->toBe([$resource], $path);
    }

    foreach (['/activity', '/invitations'] as $path) {
        expect(responseSchema($spec, 'get', $path, 200)['properties'])->toHaveKeys(['links', 'meta']);
    }
})->with($modes);

it('leaves no 2xx body untyped and no resource without fields', function (bool $installed): void {
    $spec = exportOpenApi($installed)['spec'];

    foreach ($spec['paths'] as $path => $operations) {
        foreach ($operations as $method => $operation) {
            foreach ($operation['responses'] as $status => $response) {
                if ($status < 200 || $status >= 300 || ! isset($response['content'])) {
                    continue;
                }

                $schema = $response['content']['application/json']['schema'];

                expect(isset($schema['$ref']) || isset($schema['anyOf']) || ($schema['properties'] ?? []) !== [])
                    ->toBeTrue("{$method} {$path} {$status} is untyped: ".json_encode($schema));
            }
        }
    }

    foreach ($spec['components']['schemas'] as $name => $schema) {
        if (str_ends_with($name, 'Resource')) {
            // The passkey options are typed by the passkeys package's DTOs; today an object.
            expect(($schema['properties'] ?? []) !== [] || isset($schema['additionalProperties']))->toBeTrue("{$name} has no fields");
        }
    }
})->with($modes);

it('warns only about the resource that wraps the account contract', function (bool $installed): void {
    // An interface is no class the generator can resolve; the `me` controller documents
    // the shape through `@response` instead.
    expect(exportOpenApi($installed)['diagnostics'])->toBe(['JR001 '.AccountResource::class]);
})->with($modes);

it('documents the error body on every package route through the optional extension', function (): void {
    Route::get('users/auth/host-health', static fn (): array => ['ok' => true]);

    $spec = exportOpenApi(true)['spec'];
    $error = schemaComponent($spec, 'AuthError');

    expect($error['required'])->toBe(['message', 'code'])
        ->and($error['properties'])->toHaveKeys(['message', 'code', 'errors', 'attempts_left', 'retry_after', 'methods'])
        ->and($error['properties']['code']['enum'])->toContain('invalid_credentials', 'factor_failed', 'too_many_attempts', 'refresh_invalid', 'misconfigured')
        ->and($spec['paths']['/host-health']['get']['responses'])->not->toHaveKey('default');

    foreach ($spec['paths'] as $path => $operations) {
        if ($path === '/host-health') {
            continue;
        }

        foreach ($operations as $method => $operation) {
            expect(basename($operation['responses']['default']['content']['application/json']['schema']['$ref'] ?? ''))->toBe('AuthError', "{$method} {$path}");

            if (isset($operation['responses']['422'])) {
                expect(schemaRefs(responseSchema($spec, $method, $path, 422)))->toBe(['AuthError', 'inline'], "{$method} {$path}");
            }
        }
    }
});

it('documents the field names the endpoints actually send', function (): void {
    Notification::fake();
    $spec = exportOpenApi(true)['spec'];
    $documented = static fn (string $schema): array => array_keys(schemaComponent($spec, $schema)['properties']);

    $user = User::factory()->create();
    $tokens = $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'correct-horse-battery'])->assertOk()->json();

    expect(array_keys($tokens))->toBe($documented('TokenPairResource'))
        ->and(array_keys($this->getJson('/users/auth/me', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertOk()->json('data')))->toBe($documented('AccountResource'));

    $challenged = User::factory()->create();
    enableTotp($challenged);
    $challenge = $this->postJson('/users/auth/login', ['identifier' => $challenged->email, 'password' => 'correct-horse-battery'])->assertOk()->json();

    expect(array_keys($challenge))->toBe($documented('ChallengeResource'))
        ->and(array_keys($challenge['remaining'][0]))->toBe(['step', 'methods']);

    $error = $this->postJson('/users/auth/login', ['identifier' => $user->email, 'password' => 'wrong'])->assertStatus(422)->json();

    expect(array_diff(array_keys($error), $documented('AuthError')))->toBe([]);
});
