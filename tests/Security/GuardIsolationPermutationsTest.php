<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Challenges\FindActiveChallenge;
use RoundlyConsulting\Auth\Actions\Email\SendEmailVerification;
use RoundlyConsulting\Auth\Actions\Email\VerifyEmail;
use RoundlyConsulting\Auth\Actions\Invitations\PreviewInvitation;
use RoundlyConsulting\Auth\Actions\Passwords\RequestPasswordReset;
use RoundlyConsulting\Auth\Actions\Passwords\ResetPassword;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordResetData;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Notifications\EmailOtpNotification;
use RoundlyConsulting\Auth\Notifications\ResetPasswordNotification;
use RoundlyConsulting\Auth\Notifications\VerifyEmailNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Every secret a users account holds is refused by the clients guard — and still works
 * on its own guard afterwards. Same primary key and address on both tables.
 */
beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('clients', [
        'login.email_otp' => true, 'login.password' => true, 'passwords.reset.enabled' => true,
        'invitations.enabled' => true, 'two_factor.mode' => 'optional',
    ]);
    $this->user = User::factory()->unverified()->create();
    $this->client = Client::factory()->unverified()->create(['id' => $this->user->getKey(), 'email' => $this->user->email]);
});

it('refuses a users email code on clients', function (): void {
    Authentication::guard('users')->requestEmailOtp($this->user->email, sessionContext());
    $code = (string) sentNotification($this->user, EmailOtpNotification::class)->data->code;

    expect(fn () => Authentication::guard('clients')->verifyEmailOtp($this->user->email, $code, sessionContext()))->toThrow(InvalidCode::class)
        ->and(Authentication::guard('users')->verifyEmailOtp($this->user->email, $code, sessionContext())->isAuthenticated())->toBeTrue();
});

it('refuses a users reset link on clients', function (): void {
    $this->configureGuard('users', ['passwords.reset.enabled' => true]);
    app(RequestPasswordReset::class)->execute('users', $this->user->email, sessionContext());
    $token = tokenFromUrl(sentNotification($this->user, ResetPasswordNotification::class)->data->url);

    expect(fn () => app(ResetPassword::class)->execute('clients', new PasswordResetData($token, 'a-brand-new-passphrase', sessionContext())))->toThrow(InvalidOneTimeToken::class)
        ->and(app(ResetPassword::class)->execute('users', new PasswordResetData($token, 'a-brand-new-passphrase', sessionContext())))->toBeNull();
});

it('refuses a users verification link on clients', function (): void {
    app(SendEmailVerification::class)->execute('users', $this->user);
    $token = tokenFromUrl(sentNotification($this->user, VerifyEmailNotification::class)->data->url);

    expect(fn () => app(VerifyEmail::class)->execute('clients', $token, null, sessionContext()))->toThrow(InvalidOneTimeToken::class)
        ->and(app(VerifyEmail::class)->execute('users', $token, null, sessionContext())->hasVerifiedEmail())->toBeTrue()
        ->and($this->client->fresh()?->hasVerifiedEmail())->toBeFalse();
});

it('refuses a users invitation on clients', function (): void {
    $link = Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com', send: false));

    expect(fn () => app(PreviewInvitation::class)->execute('clients', $link->token))->toThrow(InvalidInvitation::class)
        ->and(app(PreviewInvitation::class)->execute('users', $link->token)->email)->toBe('invitee@example.com');
});

it('refuses a users challenge token on clients', function (): void {
    enableTotp($this->user);
    $challenge = Authentication::guard('users')->attempt(new PasswordCredentials($this->user->email, 'correct-horse-battery'), sessionContext())->challenge;

    expect(fn () => app(FindActiveChallenge::class)->execute('clients', $challenge->token, sessionContext()))->toThrow(ChallengeInvalid::class)
        ->and(app(FindActiveChallenge::class)->execute('users', $challenge->token, sessionContext())->guard)->toBe('users');
});

it('keeps disabled features absent per guard', function (): void {
    $this->configureGuard('clients', ['invitations.enabled' => false]);

    expect(fn () => app(PreviewInvitation::class)->execute('clients', 'x'))->toThrow(LoginMethodDisabled::class);
});
