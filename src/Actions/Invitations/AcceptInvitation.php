<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Email\SendEmailVerification;
use RoundlyConsulting\Auth\Actions\Login\CompleteFirstFactor;
use RoundlyConsulting\Auth\Actions\Registration\CreateAccount;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\CreatesAccounts;
use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationResult;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\AccountRegistered;
use RoundlyConsulting\Auth\Events\InvitationAccepted;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Exceptions\InvalidInvitation;
use RoundlyConsulting\Auth\Exceptions\InvitationAddressTaken;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\RegistrationValidator;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Accepts an invitation by creating its account. The claim (`accepted_at … WHERE
 * accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now`) precedes the
 * account creation in ONE transaction, so two concurrent accepts create one account.
 * The invited address counts as verified (possession proven); with `lock_email = false`
 * another address may be used, stored unverified. An address that already has an
 * account rolls the claim back: uniform `invalid_invitation`, and a notice to that
 * address.
 *
 * Like registration, the answer after the account exists is never an error: an
 * unverified address under `required_for_login`, or a forced enrolment the challenge
 * cannot run, answers `verification_required` (unverified) / `accepted` (verified) —
 * the account signs in once it can.
 */
final readonly class AcceptInvitation
{
    public function __construct(
        private GuardRegistry $guards,
        private Container $container,
        private Throttle $throttle,
        private PreviewInvitation $preview,
        private RegistrationValidator $validator,
        private SendEmailVerification $sendVerification,
        private CompleteFirstFactor $completeFirstFactor,
        private NotificationDispatcher $notifications,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(string $guard, AcceptInvitationData $data): RegistrationResult
    {
        $config = $this->guards->get($guard);
        $this->throttle->attempt($config, [ThrottleKind::Registration], null, $data->context, ActivityType::InvitationAccepted);

        $invitation = $this->preview->execute($guard, $data->token);
        $accounts = new AccountRepository($config);

        $email = ! $config->invitationLocksEmail() && $data->email !== null
            ? $accounts->normalizeEmail($data->email)
            : $invitation->email;
        $verified = $email === $invitation->email;

        $attributes = $this->validator->validate($config, $email, $data->password, $data->attributes);

        try {
            $account = AccountModels::of($accounts->newModel())->getConnection()->transaction(
                fn (): Account => $this->claimAndCreate($config, $accounts, $invitation, $email, $verified, $data, $attributes),
            );
        } catch (InvitationAddressTaken|UniqueConstraintViolationException $e) {
            $this->exists($config, $email, $invitation);

            throw new InvalidInvitation($e);
        }

        $invitation->refresh();

        event(new AccountRegistered($guard, $account, LoginMethod::Invitation));
        event(new InvitationAccepted($guard, $invitation, $account));

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::InvitationAccepted,
            outcome: ActivityOutcome::Succeeded,
            context: $data->context,
            method: LoginMethod::Invitation->value,
            account: $account,
            identifier: $email,
        ));

        if (! $verified && $config->verificationMode() !== EmailVerificationMode::Off) {
            $this->sendVerification->execute($guard, $account, $data->context);
        }

        if (! $verified && $config->verificationMode() === EmailVerificationMode::RequiredForLogin) {
            return new RegistrationResult(RegistrationStatus::VerificationRequired);
        }

        try {
            $login = $this->completeFirstFactor->execute($config, $account, LoginMethod::Invitation, $data->context, $verified ? [AuthMethodReference::Email] : []);
        } catch (EnrolmentRequired) {
            return new RegistrationResult($verified ? RegistrationStatus::Accepted : RegistrationStatus::VerificationRequired);
        }

        return new RegistrationResult(RegistrationStatus::Authenticated, $login);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function claimAndCreate(GuardConfig $guard, AccountRepository $accounts, Invitation $invitation, string $email, bool $verified, AcceptInvitationData $data, array $attributes): Account
    {
        $now = CarbonImmutable::now();

        $claimed = Models::invitations()
            ->whereKey($invitation->getKey())
            ->whereNull('accepted_at')
            ->whereNull('revoked_at')
            ->where('expires_at', '>', $now)
            ->update(['accepted_at' => $now]);

        if ($claimed === 0) {
            throw new InvalidInvitation;
        }

        if ($accounts->emailTaken($email)) {
            // Rolls the claim back with the transaction.
            throw new InvitationAddressTaken;
        }

        $account = $this->creator($guard)->create($guard, new NewAccountData(
            email: $email,
            password: $data->password,
            locale: $guard->storesLocaleOnRegistration() ? ($invitation->locale ?? $data->context->locale) : null,
            timezone: $data->context->timezone,
            emailVerified: $verified,
            attributes: $attributes,
        ));

        $model = AccountModels::of($account);

        Models::invitations()->whereKey($invitation->getKey())->update([
            'account_type' => $model->getMorphClass(),
            'account_id' => $model->getKey(),
        ]);

        return $account;
    }

    private function exists(GuardConfig $guard, string $email, Invitation $invitation): void
    {
        $this->notifications->sendTo($guard, NotificationType::AccountExists, $email, new NotificationData($guard->name()), $invitation->locale);
    }

    private function creator(GuardConfig $guard): CreatesAccounts
    {
        $class = $guard->accountCreator() ?? CreateAccount::class;
        $creator = $this->container->make($class);

        return $creator instanceof CreatesAccounts ? $creator : $this->container->make(CreateAccount::class);
    }
}
