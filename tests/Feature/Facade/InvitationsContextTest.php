<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Invitations\ResendInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\RevokeInvitation;
use RoundlyConsulting\Auth\Actions\Invitations\SendInvitation;
use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\Enums\InvitationStatus;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Notifications\InvitationNotification;

beforeEach(function (): void {
    Notification::fake();
});

it('returns the link it mails', function (): void {
    $link = Authentication::invitations()->create(new InvitationData('invitee@example.com', ['role' => 'vet']));

    Notification::assertSentOnDemand(InvitationNotification::class, fn (InvitationNotification $notification): bool => $notification->data->url === $link->url);
    expect($link->invitation->email)->toBe('invitee@example.com')
        ->and($link->invitation->send_count)->toBe(1)
        ->and(Authentication::invitations()->preview($link->token)->is($link->invitation))->toBeTrue();
});

it('hands the link to the host instead of mailing it', function (): void {
    $link = Authentication::invitations()->create(new InvitationData('invitee@example.com', send: false));

    Notification::assertNothingSent();

    $result = Authentication::invitations()->accept(new AcceptInvitationData($link->token, 'a-long-enough-passphrase', sessionContext()));

    expect($result->status)->toBe(RegistrationStatus::Authenticated)
        ->and($link->invitation->fresh()?->status())->toBe(InvitationStatus::Accepted);
});

it('lists, finds, re-links and revokes the guard invitations', function (): void {
    $first = Authentication::invitations()->create(new InvitationData('a@example.com'));
    $second = Authentication::invitations()->create(new InvitationData('b@example.com'));
    $invitations = Authentication::guard('users')->invitations();

    expect($invitations->paginate()->total())->toBe(2)
        ->and($invitations->find((int) $first->invitation->getKey())?->email)->toBe('a@example.com')
        ->and($invitations->find(999_999))->toBeNull();

    $copy = $invitations->link((int) $second->invitation->getKey());
    Notification::assertSentOnDemandTimes(InvitationNotification::class, 2);

    // The copyable link replaced the mailed one.
    expect(fn () => $invitations->preview($second->token))->toThrow(InvalidInvitation::class)
        ->and($invitations->preview($copy->token)->email)->toBe('b@example.com');

    $invitations->revoke($first->invitation);
    $invitations->revoke((int) $first->invitation->getKey()); // idempotent

    expect($invitations->paginate(InvitationStatus::Revoked)->total())->toBe(1)
        ->and($invitations->paginate(InvitationStatus::Pending, perPage: 1)->items())->toHaveCount(1)
        ->and(fn () => $invitations->link($first->invitation->fresh() ?? $first->invitation))->toThrow(InvalidInvitation::class)
        ->and(fn () => $invitations->resend($first->invitation->fresh() ?? $first->invitation))->toThrow(InvalidInvitation::class);
});

it('refuses another guard\'s invitation, by model or by id', function (Closure $act): void {
    $theirs = Invitation::factory()->create(['guard' => 'clients']);

    expect(fn () => $act($theirs))->toThrow(InvitationNotFound::class)
        ->and($theirs->fresh()?->revoked_at)->toBeNull()
        ->and($theirs->fresh()?->send_count)->toBe(0);
    Notification::assertNothingSent();
})->with([
    'resend' => [fn (Invitation $theirs) => Authentication::guard('users')->invitations()->resend($theirs)],
    'resend by id' => [fn (Invitation $theirs) => Authentication::guard('users')->invitations()->resend((int) $theirs->getKey())],
    'revoke' => [fn (Invitation $theirs) => Authentication::guard('users')->invitations()->revoke($theirs)],
    'revoke by id' => [fn (Invitation $theirs) => Authentication::guard('users')->invitations()->revoke((int) $theirs->getKey())],
    'link' => [fn (Invitation $theirs) => Authentication::guard('users')->invitations()->link($theirs)],
    'resend action' => [fn (Invitation $theirs) => app(ResendInvitation::class)->execute('users', $theirs)],
    'revoke action' => [fn (Invitation $theirs) => app(RevokeInvitation::class)->execute('users', $theirs)],
    'send action' => [fn (Invitation $theirs) => app(SendInvitation::class)->execute('users', $theirs)],
]);

it('never finds another guard\'s invitation', function (): void {
    $theirs = Invitation::factory()->create(['guard' => 'clients']);

    expect(Authentication::guard('users')->invitations()->find((int) $theirs->getKey()))->toBeNull()
        ->and(Authentication::guard('users')->invitations()->paginate()->total())->toBe(0);
});
