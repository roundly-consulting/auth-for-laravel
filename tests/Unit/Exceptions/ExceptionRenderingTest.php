<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Exceptions;

dataset('exceptions', [
    [Exceptions\InvalidCredentials::class, 422, 'invalid_credentials', 'identifier'],
    [Exceptions\InvalidOneTimeToken::class, 422, 'invalid_token', 'token'],
    [Exceptions\InvalidCode::class, 422, 'invalid_code', 'code'],
    [Exceptions\ChallengeInvalid::class, 422, 'challenge_invalid', 'challenge_token'],
    [Exceptions\ChallengeFactorFailed::class, 422, 'factor_failed', 'code'],
    [Exceptions\FactorNotAllowed::class, 422, 'factor_not_allowed', 'method'],
    [Exceptions\InvalidInvitation::class, 422, 'invalid_invitation', 'token'],
    [Exceptions\InvitationAddressTaken::class, 422, 'invalid_invitation', null],
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
