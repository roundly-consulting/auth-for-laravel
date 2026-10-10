<?php

declare(strict_types=1);

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Configuration\Exceptions as ExceptionsConfiguration;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Exceptions;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Tests\Fixtures\Support\ApiProblem;
use Symfony\Component\HttpFoundation\Response;

dataset('exceptions', [
    [Exceptions\InvalidCredentials::class, 422, 'invalid_credentials', 'identifier'],
    [Exceptions\InvalidOneTimeToken::class, 422, 'invalid_token', 'token'],
    [Exceptions\InvalidCode::class, 422, 'invalid_code', 'code'],
    [Exceptions\ChallengeInvalid::class, 422, 'challenge_invalid', 'challenge_token'],
    [Exceptions\ChallengeFactorFailed::class, 422, 'factor_failed', 'code'],
    [Exceptions\FactorNotAllowed::class, 422, 'factor_not_allowed', 'method'],
    [Exceptions\InvalidInvitation::class, 422, 'invalid_invitation', 'token'],
    [Exceptions\InvitationAddressTaken::class, 422, 'invalid_invitation', null],
    [Exceptions\InvitationSendLimitReached::class, 422, 'invitation_send_limit', null],
    [Exceptions\InvalidRefreshToken::class, 401, 'refresh_invalid', null],
    [Exceptions\EnrolmentRequired::class, 403, 'enrolment_required', null],
    [Exceptions\TooManyAttempts::class, 429, 'too_many_attempts', null],
    [Exceptions\AccountDisabled::class, 403, 'account_disabled', null],
    [Exceptions\AccountLocked::class, 423, 'account_locked', null],
    [Exceptions\EmailNotVerified::class, 403, 'email_not_verified', null],
    [Exceptions\LoginMethodDisabled::class, 404, 'method_disabled', null],
    [Exceptions\RegistrationClosed::class, 403, 'registration_closed', null],
    [Exceptions\InvitationRequired::class, 403, 'invitation_required', null],
    [Exceptions\ReauthenticationRequired::class, 403, 'reauthentication_required', null],
    [Exceptions\TwoFactorRequired::class, 409, 'two_factor_required', null],
    [Exceptions\LastCredential::class, 409, 'last_credential', null],
    [Exceptions\TwoFactorAlreadyEnabled::class, 409, 'two_factor_already_enabled', null],
    [Exceptions\TwoFactorNotEnabled::class, 409, 'two_factor_not_enabled', null],
    [Exceptions\PasskeyRegistrationFailed::class, 422, 'passkey_registration_failed', 'credential'],
    [Exceptions\SessionNotFound::class, 404, 'not_found', null],
    [Exceptions\PasskeyNotFound::class, 404, 'not_found', null],
    [Exceptions\InvitationNotFound::class, 404, 'not_found', null],
    [Exceptions\LoginDenied::class, 403, 'login_denied', null],
    [Exceptions\BreachCheckUnavailable::class, 503, 'password_check_unavailable', 'password'],
    [Exceptions\AuthenticationMisconfigured::class, 500, 'misconfigured', null],
    [Exceptions\GuardNotConfigured::class, 500, 'misconfigured', null],
]);

it('renders a stable code, status and translated message', function (string $class, int $status, string $code, ?string $field): void {
    $exception = new $class;
    $response = $exception->render(Request::create('/'));
    $body = $response->getData(true);

    expect($response->getStatusCode())->toBe($status)
        ->and($exception->status())->toBe($status)
        ->and($body['code'])->toBe($code)
        ->and($body['message'])->not->toBe($code)
        ->and($exception->field())->toBe($field)
        ->and($response->headers->get('Cache-Control'))->toContain('no-store');

    if ($field !== null) {
        expect($body['errors'][$field][0])->toBe($body['message']);
    }
})->with('exceptions');

it('adds its extras', function (): void {
    expect(Exceptions\InvalidCode::withAttemptsLeft(-3)->extra())->toBe(['attempts_left' => 0])
        ->and(Exceptions\ChallengeFactorFailed::withAttemptsLeft(2)->attemptsLeft())->toBe(2)
        ->and((new Exceptions\ChallengeFactorFailed)->attemptsLeft())->toBe(0)
        ->and(Exceptions\TooManyAttempts::retryAfter(30)->render(Request::create('/'))->headers->get('Retry-After'))->toBe('30')
        ->and((new Exceptions\TooManyAttempts)->retryAfterSeconds())->toBe(1)
        ->and(Exceptions\AccountLocked::retryAfter(90)->retryAfterSeconds())->toBe(90)
        ->and((new Exceptions\AccountLocked)->retryAfterSeconds())->toBe(1)
        ->and(Exceptions\AccountLocked::retryAfter(90)->render(Request::create('/'))->headers->get('Retry-After'))->toBe('90')
        ->and(Exceptions\ReauthenticationRequired::using([ReauthenticationMethod::Totp])->extra())->toBe(['methods' => ['totp']]);
});

it('keeps misconfiguration detail out of responses unless debugging, and reports it', function (): void {
    $exception = Exceptions\AuthenticationMisconfigured::because('secret detail about authentication.hash_key');

    config()->set('app.debug', false);
    expect($exception->render(Request::create('/'))->getData(true)['message'])->not->toContain('secret detail');

    config()->set('app.debug', true);
    expect($exception->render(Request::create('/'))->getData(true)['message'])->toContain('secret detail')
        ->and($exception->report())->toBeFalse()
        ->and((new Exceptions\InvalidCredentials)->report())->toBeTrue()
        ->and(Exceptions\GuardNotConfigured::named('staff')->getMessage())->toContain('[staff]');
});

it('falls back to the code when a message is missing', function (): void {
    app('translator')->addLines(['messages.errors.not_found' => 'authentication::messages.errors.not_found'], 'en', 'authentication');

    expect((new Exceptions\SessionNotFound)->getMessage())->toBeString();
});

/*
 * How a host changes the response, pinned against Laravel's own handler: `render()`
 * maps the exception first, then lets an exception that renders itself answer, and only
 * then runs the `$exceptions->render()` callbacks. So for package exceptions `map()` and
 * `respond()` work, and `render()` callbacks never run.
 */
function hostExceptions(): ExceptionsConfiguration
{
    return new ExceptionsConfiguration(app(ExceptionHandler::class));
}

it('never runs a host render() callback for a package exception', function (): void {
    $called = false;
    hostExceptions()->render(function (AuthException $e) use (&$called): JsonResponse {
        $called = true;

        return new JsonResponse(['host' => true], 400);
    });

    $response = app(ExceptionHandler::class)->render(Request::create('/'), Exceptions\TooManyAttempts::retryAfter(30));

    expect($called)->toBeFalse()
        ->and($response->getStatusCode())->toBe(429)
        ->and(json_decode((string) $response->getContent(), true)['code'])->toBe('too_many_attempts')
        ->and($response->headers->get('Retry-After'))->toBe('30');
});

it('renders the host exception a package exception is mapped to', function (): void {
    hostExceptions()->map(AuthException::class, fn (AuthException $e): Throwable => new ApiProblem($e->errorCode(), $e->getMessage(), $e->status(), $e));

    $response = app(ExceptionHandler::class)->render(Request::create('/'), new Exceptions\InvalidCredentials);

    expect($response->getStatusCode())->toBe(422)
        ->and($response->headers->get('Content-Type'))->toBe('application/problem+json')
        ->and(json_decode((string) $response->getContent(), true))->toBe(['type' => 'invalid_credentials', 'title' => 'These credentials do not match our records.', 'status' => 422]);
});

it('reports the mapped exception, so it must stay unreported itself', function (): void {
    $reported = [];
    $record = function (ApiProblem $problem) use (&$reported): void {
        $reported[] = $problem;
    };
    hostExceptions()->map(AuthException::class, fn (AuthException $e): Throwable => new ApiProblem($e->errorCode(), $e->getMessage(), $e->status(), $e, $record));

    app(ExceptionHandler::class)->report($exception = new Exceptions\InvalidCredentials);

    expect($reported)->toHaveCount(1)
        ->and($reported[0]->getPrevious())->toBe($exception);
});

it('hands a host respond() callback the response the exception rendered itself', function (): void {
    $seen = [];
    hostExceptions()->respond(function (Response $response, Throwable $e, Request $request) use (&$seen): Response {
        $seen = [$response->getStatusCode(), $e];

        if ($e instanceof AuthException) {
            $response->setContent((string) json_encode(['error' => ['code' => $e->errorCode(), 'message' => $e->getMessage()]]));
        }

        return $response;
    });

    $response = app(ExceptionHandler::class)->render(Request::create('/'), $exception = Exceptions\AccountLocked::retryAfter(90));

    expect($seen)->toBe([423, $exception])
        ->and($response->getStatusCode())->toBe(423)
        ->and($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($response->headers->get('Retry-After'))->toBe('90')
        ->and(json_decode((string) $response->getContent(), true))->toBe(['error' => ['code' => 'account_locked', 'message' => $exception->getMessage()]]);
});
