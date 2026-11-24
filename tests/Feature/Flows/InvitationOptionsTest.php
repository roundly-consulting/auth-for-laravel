<?php

declare(strict_types=1);

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationAlreadyAccepted;
use RoundlyConsulting\Auth\Exceptions\InvitationEmailMismatch;
use RoundlyConsulting\Auth\Exceptions\InvitationExpired;
use RoundlyConsulting\Auth\Exceptions\InvitationRevoked;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Notifications\InvitationNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['invitations.enabled' => true]);
});

function optionsInvite(string $email = 'invitee@example.com', array $payload = [], ?bool $replacePending = null): string
{
    return Authentication::guard('users')->invitations()
        ->create(new InvitationData($email, $payload, send: false, replacePending: $replacePending))
        ->token;
}

function acceptAs(string $token, ?string $email = null): void
{
    Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext(), email: $email));
}

function invitationMail(): InvitationNotification
{
    $sent = null;

    Notification::assertSentOnDemand(InvitationNotification::class, function (InvitationNotification $notification) use (&$sent): bool {
        $sent = $notification;

        return true;
    });

    return $sent;
}

// ── P1: invitations.reject_other_email ───────────────────────────────

it('refuses another address and keeps the invitation pending', function (): void {
    $this->configureGuard('users', ['invitations.reject_other_email' => true]);
    $token = optionsInvite();

    $this->postJson('/users/auth/invitations/accept', ['token' => $token, 'password' => 'a-long-enough-passphrase', 'email' => 'other@example.com'])
        ->assertStatus(422)
        ->assertJsonPath('code', 'invitation_email_mismatch')
        ->assertJsonValidationErrors('email');

    expect(User::query()->count())->toBe(0)
        ->and(Invitation::query()->sole()->isPending())->toBeTrue()
        ->and(LoginActivity::query()->where('type', ActivityType::InvitationAccepted)->sole())
        ->outcome->toBe(ActivityOutcome::FailedCredentials)
        ->reason->toBe('invitation_email_mismatch');

    acceptAs($token);
    expect(User::query()->sole()->email)->toBe('invitee@example.com');
});

it('accepts the invited address in another case or with spaces', function (string $email): void {
    $this->configureGuard('users', ['invitations.reject_other_email' => true]);

    acceptAs(optionsInvite(), $email);

    expect(User::query()->sole()->email)->toBe('invitee@example.com');
})->with(['  invitee@example.com ', 'Invitee@EXAMPLE.com']);

it('counts a refused address against the registration throttle', function (): void {
    $this->configureGuard('users', ['invitations.reject_other_email' => true, 'throttle.registration' => ['max' => 1, 'decay' => 60]]);
    $token = optionsInvite();

    expect(fn () => acceptAs($token, 'other@example.com'))->toThrow(InvitationEmailMismatch::class);

    expect(fn () => acceptAs($token))->toThrow(TooManyAttempts::class)
        ->and(Invitation::query()->sole()->isPending())->toBeTrue();
});

it('ignores another address when the option is off or the address is unlocked', function (array $settings, string $expected): void {
    $this->configureGuard('users', $settings);

    acceptAs(optionsInvite(), 'other@example.com');

    expect(User::query()->sole()->email)->toBe($expected);
})->with([
    'option off' => [['invitations.reject_other_email' => false], 'invitee@example.com'],
    'lock_email false' => [['invitations.reject_other_email' => true, 'invitations.lock_email' => false], 'other@example.com'],
]);

// ── P2: invitations.mail_payload_keys ────────────────────────────────

it('renders listed payload keys in the mail', function (): void {
    $this->configureGuard('users', ['invitations.mail_payload_keys' => ['company_name', 'seats']]);
    app('translator')->addLines([
        'notifications.invitation.subject' => 'Join :company_name',
        'notifications.invitation.intro' => ':company_name has :seats seats for you.',
    ], 'en', 'authentication');

    Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com', ['company_name' => 'Acme', 'seats' => 3]));
    $mail = invitationMail()->toMail(new AnonymousNotifiable);

    expect($mail->subject)->toBe('Join Acme')
        ->and($mail->introLines[0])->toBe('Acme has 3 seats for you.');
});

it('keeps unlisted payload keys out of the mail', function (): void {
    $this->configureGuard('users', ['invitations.mail_payload_keys' => ['company_name']]);
    app('translator')->addLines(['notifications.invitation.intro' => 'Role: :role'], 'en', 'authentication');

    Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com', ['company_name' => 'Acme', 'role' => 'admin']));
    $notification = invitationMail();

    expect($notification->data->replacements)->toBe(['company_name' => 'Acme'])
        ->and($notification->toMail(new AnonymousNotifiable)->introLines[0])->toBe('Role: :role');
});

it('renders an array, null or missing value as empty and cuts long values', function (): void {
    $this->configureGuard('users', ['invitations.mail_payload_keys' => ['list', 'nothing', 'missing', 'long']]);
    app('translator')->addLines(['notifications.invitation.intro' => '[:list][:nothing][:missing]'], 'en', 'authentication');

    Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com', ['list' => ['a'], 'nothing' => null, 'long' => str_repeat('é', 300)]));
    $notification = invitationMail();

    expect($notification->toMail(new AnonymousNotifiable)->introLines[0])->toBe('[][][]')
        ->and($notification->data->replacements['long'])->toBe(str_repeat('é', 255));
});

it('sends no payload replacements by default', function (): void {
    Authentication::guard('users')->invitations()->create(new InvitationData('invitee@example.com', ['company_name' => 'Acme']));

    expect(invitationMail()->data->replacements)->toBe([]);
});

// ── P3: invitations.distinct_errors ──────────────────────────────────

dataset('dead invitations', [
    'accepted' => [static function (string $token): void {
        acceptAs($token);
    }, 'invitation_accepted', InvitationAlreadyAccepted::class],
    'revoked' => [static function (): void {
        Authentication::guard('users')->invitations()->revoke(Invitation::query()->sole());
    }, 'invitation_revoked', InvitationRevoked::class],
    'expired' => [static function (): void {
        test()->travel(8)->days();
    }, 'invitation_expired', InvitationExpired::class],
]);

it('tells why a link no longer works', function (Closure $kill, string $code, string $exception): void {
    $this->configureGuard('users', ['invitations.distinct_errors' => true]);
    $token = optionsInvite();
    $kill($token);

    $this->postJson('/users/auth/invitations/preview', ['token' => $token])->assertStatus(422)->assertJsonPath('code', $code);
    $this->postJson('/users/auth/invitations/accept', ['token' => $token, 'password' => 'a-long-enough-passphrase'])->assertStatus(422)->assertJsonPath('code', $code);
    expect(fn () => acceptAs($token))->toThrow($exception);
})->with('dead invitations');

it('answers invalid_invitation for every dead link by default', function (Closure $kill): void {
    $token = optionsInvite();
    $kill($token);

    $this->postJson('/users/auth/invitations/preview', ['token' => $token])->assertStatus(422)->assertJsonPath('code', 'invalid_invitation');
    expect(fn () => acceptAs($token))->toThrow(InvalidInvitation::class);
})->with('dead invitations');

it('keeps unknown and replaced links invalid_invitation', function (): void {
    $this->configureGuard('users', ['invitations.distinct_errors' => true]);
    $replaced = optionsInvite();
    Authentication::guard('users')->invitations()->link(Invitation::query()->sole());

    foreach (['nope', $replaced] as $token) {
        $this->postJson('/users/auth/invitations/preview', ['token' => $token])->assertStatus(422)->assertJsonPath('code', 'invalid_invitation');
        $this->postJson('/users/auth/invitations/accept', ['token' => $token, 'password' => 'a-long-enough-passphrase'])->assertStatus(422)->assertJsonPath('code', 'invalid_invitation');
    }
});

it('never tells another guard why its link died', function (): void {
    $this->configureGuard('users', ['invitations.distinct_errors' => true]);
    $this->configureGuard('clients', ['invitations.enabled' => true, 'invitations.distinct_errors' => true]);
    $token = optionsInvite();
    acceptAs($token);

    expect(fn () => Authentication::guard('clients')->invitations()->preview($token))->toThrow(InvalidInvitation::class);
});

// ── P4: InvitationData::$replacePending ──────────────────────────────

it('leaves an open invitation pending when replacePending is false', function (): void {
    optionsInvite();
    optionsInvite(replacePending: false);

    expect(Invitation::query()->pending()->count())->toBe(2);
});

it('follows the guard option when replacePending is null', function (bool $guardOption, int $pending): void {
    $this->configureGuard('users', ['invitations.replace_pending' => $guardOption]);
    optionsInvite();
    optionsInvite();

    expect(Invitation::query()->pending()->count())->toBe($pending);
})->with([
    'replace_pending true' => [true, 1],
    'replace_pending false' => [false, 2],
]);

it('replaces an open invitation when replacePending is true against the guard option', function (): void {
    $this->configureGuard('users', ['invitations.replace_pending' => false]);
    optionsInvite();
    optionsInvite(replacePending: true);

    expect(Invitation::query()->pending()->count())->toBe(1);
});
