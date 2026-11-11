<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PendingChallenge;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\LoginStatus;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\PasskeyCreationOptionsResource;
use RoundlyConsulting\Auth\Http\Resources\PasskeyOptionsResource;
use RoundlyConsulting\Auth\Http\Resources\PasskeyRequestOptionsResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Http\Responses\LoginResponse;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

function sampleTokens(): TokenPair
{
    return new TokenPair('access', CarbonImmutable::now()->addMinutes(15), 'refresh', CarbonImmutable::now()->addDays(30), 'session-1', 'jti-1');
}

function sampleChallenge(): PendingChallenge
{
    return new PendingChallenge(
        'challenge-token',
        CarbonImmutable::now()->addMinutes(10),
        LoginMethod::Password,
        [ChallengeStep::SecondFactor],
        [new ChallengeRequirement(ChallengeStep::EnrolPasskey, [FactorMethod::PasskeyEnrolment])],
        4,
    );
}

it('renders a login result the same through make() and resource()', function (LoginResult $result, string $resource): void {
    $request = Request::create('/');
    $made = LoginResponse::make($result, $request);

    expect(LoginResponse::resource($result))->toBeInstanceOf($resource)
        ->and($made->getStatusCode())->toBe(200)
        ->and($made->getContent())->toBe(LoginResponse::resource($result)->toResponse($request)->getContent());
})->with([
    'tokens' => [fn (): LoginResult => new LoginResult(LoginStatus::Authenticated, tokens: sampleTokens()), TokenPairResource::class],
    'challenge' => [fn (): LoginResult => new LoginResult(LoginStatus::ChallengeRequired, challenge: sampleChallenge()), ChallengeResource::class],
]);

it('renders the token pair unwrapped with a non-negative expires_in', function (): void {
    CarbonImmutable::setTestNow('2026-11-11 12:00:00');
    $expired = new TokenPair('access', CarbonImmutable::now()->subMinute(), 'refresh', CarbonImmutable::now()->addDay(), 'session-1', 'jti-1');

    expect(LoginResponse::tokens(sampleTokens(), Request::create('/'))->getData(true))
        ->toMatchArray(['status' => 'authenticated', 'token_type' => 'Bearer', 'access_token' => 'access', 'expires_in' => 900, 'session_id' => 'session-1'])
        ->and((new TokenPairResource($expired))->toArray(Request::create('/'))['expires_in'])->toBe(0);

    CarbonImmutable::setTestNow();
});

it('renders the challenge steps as their wire values', function (): void {
    expect((new ChallengeResource(sampleChallenge()))->toArray(Request::create('/')))->toMatchArray([
        'status' => 'challenge',
        'attempts_left' => 4,
        'method' => 'password',
        'completed' => ['second_factor'],
        'remaining' => [['step' => 'enrol_passkey', 'methods' => ['passkey_enrolment']]],
    ]);
});

it('keeps the status and credential-change helpers for host controllers', function (): void {
    $request = Request::create('/');

    expect(LoginResponse::status('sent')->getStatusCode())->toBe(202)
        ->and(LoginResponse::status('sent')->getData(true))->toBe(['status' => 'sent'])
        ->and(LoginResponse::status('verified', 200)->getStatusCode())->toBe(200)
        ->and(LoginResponse::withTokens(['status' => 'changed'], null, $request)->getData(true))->toBe(['status' => 'changed', 'tokens' => null])
        ->and(LoginResponse::withTokens(['status' => 'changed'], sampleTokens(), $request, 201)->getStatusCode())->toBe(201)
        ->and(LoginResponse::withTokens(['status' => 'changed'], sampleTokens(), $request)->getData(true)['tokens'])
        ->toBe((new TokenPairResource(sampleTokens()))->toArray($request));
});

it('renders the passkey options the same through the base and the typed resources', function (): void {
    $request = Request::create('/');
    $get = new RequestOptionsData('ceremony', 'app.test', 'challenge', 60000, UserVerification::Required);
    $create = new CreationOptionsData('ceremony', 'app.test', 'App', 'handle', 'ada@example.com', 'Ada', 'challenge', [-7], 60000, AttestationConveyance::None, UserVerification::Required);

    expect((new PasskeyRequestOptionsResource($get))->toResponse($request)->getContent())->toBe((new PasskeyOptionsResource($get))->toResponse($request)->getContent())
        ->and((new PasskeyCreationOptionsResource($create))->toResponse($request)->getContent())->toBe((new PasskeyOptionsResource($create))->toResponse($request)->getContent())
        ->and((new PasskeyRequestOptionsResource($get))->toArray($request))->toBe($get->jsonSerialize());
});
