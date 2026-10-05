<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Notification;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Events\InvitationAccepted;
use RoundlyConsulting\Auth\Events\InvitationSent;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Notifications\AccountExistsNotification;
use RoundlyConsulting\Auth\Notifications\InvitationNotification;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

beforeEach(function (): void {
    Notification::fake();
    $this->configureGuard('users', ['invitations.preview_payload_keys' => ['team'], 'locale.supported' => ['en', 'sk']]);
});

function invite(string $email = 'invitee@example.com', array $payload = ['role' => 'vet', 'team' => 'Clinic']): string
{
    $link = Authentication::guard('users')->invitations()->create(new InvitationData($email, $payload, locale: 'sk'));

    $url = null;

    Notification::assertSentOnDemand(InvitationNotification::class, function (InvitationNotification $notification) use (&$url): bool {
        $url = $notification->data->url;

        return true;
    });

    // The link create() returns is the one it mailed.
    expect($link->url)->toBe($url)
        ->and($link->token)->toBe(tokenFromUrl($url));

    return $link->token;
}

it('previews and accepts an invitation, creating a verified account', function (): void {
    Event::fake([InvitationAccepted::class]);
    $token = invite();

    $this->postJson('/users/auth/invitations/preview', ['token' => $token])
        ->assertOk()
        ->assertExactJson(['email' => 'invitee@example.com', 'guard' => 'users', 'expires_at' => Invitation::query()->sole()->expires_at->toIso8601ZuluString(), 'payload' => ['team' => 'Clinic']]);

    $this->postJson('/users/auth/invitations/accept', ['token' => $token, 'password' => 'a-long-enough-passphrase'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertOk()
        ->assertJsonPath('status', 'authenticated');

    $user = User::query()->sole();

    expect($user->hasVerifiedEmail())->toBeTrue()
        ->and($user->accountLocale())->toBe('sk')
        ->and(Invitation::query()->sole()->account_id)->toBe($user->getKey());
    Event::assertDispatched(InvitationAccepted::class, fn (InvitationAccepted $event): bool => $event->invitation->payload === ['role' => 'vet', 'team' => 'Clinic']);
});

it('is single use', function (): void {
    $token = invite();
    Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext()));

    Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext()));
})->throws(InvalidInvitation::class);

it('expires, and dies when revoked or re-sent', function (): void {
    $token = invite();
    $invitation = Invitation::query()->sole();

    $link = Authentication::guard('users')->invitations()->link($invitation);
    expect(fn () => Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext())))->toThrow(InvalidInvitation::class);

    Authentication::guard('users')->invitations()->revoke($invitation);
    expect(fn () => Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($link->token, 'a-long-enough-passphrase', sessionContext())))->toThrow(InvalidInvitation::class);

    $fresh = invite('late@example.com');
    $this->travel(8)->days();
    expect(fn () => Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($fresh, 'a-long-enough-passphrase', sessionContext())))->toThrow(InvalidInvitation::class);
});

it('replaces a pending invitation for the same address', function (): void {
    $first = invite();
    invite();

    expect(Invitation::query()->whereNotNull('revoked_at')->count())->toBe(1);
    $this->postJson('/users/auth/invitations/preview', ['token' => $first])->assertStatus(422)->assertJsonPath('code', 'invalid_invitation');
});

it('keeps the address locked, or stores another one unverified when unlocked', function (): void {
    $token = invite();
    Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext(), email: 'other@example.com'));
    expect(User::query()->sole()->email)->toBe('invitee@example.com');

    $this->configureGuard('users', ['invitations.lock_email' => false]);
    $token = invite('second@example.com');
    $result = Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext(), email: 'Chosen@Example.com'));

    $user = User::query()->where('email', 'chosen@example.com')->sole();
    expect($user->hasVerifiedEmail())->toBeFalse()
        ->and(claimsOf($result->login->tokens)->authMethods())->toBe([]);
});

it('refuses an existing address with a uniform error and a notice', function (): void {
    $this->configureGuard('users', ['invitations.allow_existing_email' => true]);
    $token = invite('taken@example.com');
    User::factory()->create(['email' => 'taken@example.com']);

    expect(fn () => Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext())))->toThrow(InvalidInvitation::class)
        ->and(Invitation::query()->sole()->accepted_at)->toBeNull();

    Notification::assertSentOnDemand(AccountExistsNotification::class);
});

it('mails a taken address chosen at acceptance once per cooldown, shared with registration', function (): void {
    $this->configureGuard('users', ['invitations.lock_email' => false, 'registration.login_after' => false, 'throttle.registration.max' => 100]);
    User::factory()->create(['email' => 'taken@example.com']);
    $token = invite();
    $accept = static fn () => Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext(), email: 'taken@example.com'));

    expect($accept)->toThrow(InvalidInvitation::class)
        ->and($accept)->toThrow(InvalidInvitation::class);
    Authentication::guard('users')->register(new RegistrationData('taken@example.com', 'a-long-enough-passphrase', sessionContext()));

    Notification::assertSentOnDemandTimes(AccountExistsNotification::class, 1);

    $this->travel(601)->seconds();
    expect($accept)->toThrow(InvalidInvitation::class);

    Notification::assertSentOnDemandTimes(AccountExistsNotification::class, 2);
});

it('refuses to invite an existing address unless allowed', function (): void {
    User::factory()->create(['email' => 'taken@example.com']);

    expect(fn () => Authentication::guard('users')->invitations()->create(new InvitationData('taken@example.com')))->toThrow(ValidationException::class);
});

it('enforces the resend cooldown and the send cap', function (): void {
    $this->configureGuard('users', ['invitations.max_sends' => 2, 'invitations.resend_cooldown' => 60]);
    CarbonImmutable::setTestNow('2026-09-26 10:00:00');
    invite();
    $invitation = Invitation::query()->sole();

    expect(fn () => Authentication::guard('users')->invitations()->resend($invitation))->toThrow(TooManyAttempts::class);

    CarbonImmutable::setTestNow('2026-09-26 10:01:00');
    $link = Authentication::guard('users')->invitations()->resend((int) $invitation->getKey());
    expect($link->url)->toContain('#token=');

    CarbonImmutable::setTestNow('2026-09-26 10:05:00');
    expect(fn () => Authentication::guard('users')->invitations()->resend((int) $invitation->getKey()))->toThrow(TooManyAttempts::class);
    CarbonImmutable::setTestNow();
});

it('manages invitations over http behind the gate', function (): void {
    $admin = User::factory()->create();
    $pair = issuePair($admin);

    $this->getJson('/users/auth/invitations', bearer($pair))->assertForbidden();

    Gate::define('authentication.invitations.manage', fn (User $user): bool => $user->is($admin));

    $id = $this->postJson('/users/auth/invitations', ['email' => 'new@example.com', 'payload' => ['role' => 'staff']], bearer($pair))
        ->assertCreated()
        ->assertJsonPath('data.status', 'pending')
        ->assertJsonPath('data.send_count', 1)
        ->json('data.id');

    expect(Invitation::query()->sole()->inviter_id)->toBe($admin->getKey());

    $this->getJson('/users/auth/invitations?status=pending', bearer($pair))->assertOk()->assertJsonCount(1, 'data');
    $this->travel(2)->minutes();
    $this->postJson("/users/auth/invitations/{$id}/resend", [], bearer($pair))->assertOk()->assertJsonStructure(['status', 'url']);
    $this->deleteJson("/users/auth/invitations/{$id}", [], bearer($pair))->assertNoContent();
    $this->deleteJson('/users/auth/invitations/999', [], bearer($pair))->assertNotFound();
    $this->deleteJson('/users/auth/invitations/abc', [], bearer($pair))->assertNotFound();
    $this->postJson("/users/auth/invitations/{$id}/resend", [], bearer($pair))->assertStatus(422);
});

it('returns the link of an unsent invitation over http, and counts no send that never happened', function (): void {
    Event::fake([InvitationSent::class]);
    $admin = User::factory()->create();
    $pair = issuePair($admin);
    Gate::define('authentication.invitations.manage', fn (User $user): bool => $user->is($admin));

    $response = $this->postJson('/users/auth/invitations', ['email' => 'slack@example.com', 'send' => false], bearer($pair))
        ->assertCreated()
        ->assertJsonPath('data.send_count', 0)
        ->assertJsonPath('data.last_sent_at', null);

    Notification::assertNothingSent();
    Event::assertNotDispatched(InvitationSent::class);
    expect(Authentication::guard('users')->invitations()->preview(tokenFromUrl($response->json('url')))->email)->toBe('slack@example.com');

    // Nothing was mailed, so the first real send is neither cooled down nor capped early.
    $this->postJson('/users/auth/invitations/'.$response->json('data.id').'/resend', [], bearer($pair))->assertOk();
    Event::assertDispatchedTimes(InvitationSent::class, 1);
    expect(Invitation::query()->sole()->send_count)->toBe(1);
});

it('returns the mailed link too when creating over http', function (): void {
    $admin = User::factory()->create();
    $pair = issuePair($admin);
    Gate::define('authentication.invitations.manage', fn (User $user): bool => $user->is($admin));

    $url = $this->postJson('/users/auth/invitations', ['email' => 'mail@example.com'], bearer($pair))
        ->assertCreated()
        ->assertJsonPath('data.send_count', 1)
        ->json('url');

    Notification::assertSentOnDemand(InvitationNotification::class, fn (InvitationNotification $notification): bool => $notification->data->url === $url);
});

it('lets two concurrent accepts create exactly one account', function (): void {
    $token = invite();
    $invitation = Invitation::query()->sole();

    // The loser's view: the claim already happened.
    Invitation::query()->whereKey($invitation->getKey())->update(['accepted_at' => now()]);

    expect(fn () => Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext())))->toThrow(InvalidInvitation::class)
        ->and(User::query()->count())->toBe(0);
});

it('answers a pending verification, not an error, once the unverified account exists', function (array $settings, string $status): void {
    $this->configureGuard('users', ['invitations.lock_email' => false, ...$settings]);
    $token = invite();

    $this->postJson('/users/auth/invitations/accept', ['token' => $token, 'password' => 'a-long-enough-passphrase', 'email' => 'other@example.com'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertStatus(202)
        ->assertExactJson(['status' => $status]);

    expect(User::query()->where('email', 'other@example.com')->exists())->toBeTrue()
        ->and(Invitation::query()->sole()->accepted_at)->not->toBeNull();
})->with([
    'verification required for login' => [['verification.mode' => 'required_for_login'], 'verification_required'],
    'forced enrolment of an unverified address' => [['two_factor.mode' => 'required'], 'verification_required'],
]);

it('answers accepted when a forced enrolment cannot happen in the challenge', function (): void {
    $this->configureGuard('users', ['two_factor.mode' => 'required', 'challenge.allow_enrolment' => false]);
    $token = invite();

    $result = Authentication::guard('users')->invitations()->accept(new AcceptInvitationData($token, 'a-long-enough-passphrase', sessionContext()));

    expect($result->status)->toBe(RegistrationStatus::Accepted)
        ->and($result->login)->toBeNull()
        ->and(User::query()->sole()->hasVerifiedEmail())->toBeTrue();
});

it('creates no account through an invitation while registration is closed', function (): void {
    $token = invite();
    $this->configureGuard('users', ['registration.mode' => 'closed']);

    $this->postJson('/users/auth/invitations/accept', ['token' => $token, 'password' => 'a-long-enough-passphrase'], ['User-Agent' => 'PestBrowser/1.0'])
        ->assertForbidden()
        ->assertJsonPath('code', 'registration_closed');

    expect(User::query()->count())->toBe(0)
        ->and(Invitation::query()->sole()->accepted_at)->toBeNull();
});

it('refuses an invitation locale the guard does not support', function (): void {
    expect(fn () => Authentication::guard('users')->invitations()->create(new InvitationData('x@example.com', [], locale: 'zz-ZZ')))->toThrow(ValidationException::class)
        ->and(fn () => Authentication::guard('users')->invitations()->create(new InvitationData('y@example.com', [], locale: 'sk/../x')))->toThrow(ValidationException::class);

    $admin = User::factory()->create();
    Gate::define('authentication.invitations.manage', fn (User $user): bool => $user->is($admin));

    $this->postJson('/users/auth/invitations', ['email' => 'z@example.com', 'locale' => 'zz'], bearer(issuePair($admin)))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['locale']);

    expect(Invitation::query()->count())->toBe(0);
    Notification::assertNothingSent();
});
