<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passwords;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Login\CompleteFirstFactor;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\ConsumeOneTimeToken;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordResetData;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\PasswordReset;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\PasswordWriter;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Resets a password through an emailed link. The policy is checked BEFORE the link is
 * consumed (a weak password must not burn it). The reset proves mailbox possession, so
 * the address counts as verified (and a hard lock lifts, per `lockout.reset_unlocks`);
 * every session dies (`invalidation.password_reset`, default `all`). With
 * `passwords.reset.login_after` the user is signed in — always through the account's
 * second factor: a mailbox compromise must never bypass it.
 */
final readonly class ResetPassword
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private SecretHasher $hasher,
        private ValidatePasswordPolicy $policy,
        private ConsumeOneTimeToken $consume,
        private InvalidateAccountTokens $invalidate,
        private CompleteFirstFactor $completeFirstFactor,
        private NotificationDispatcher $notifications,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(string $guard, PasswordResetData $data): ?LoginResult
    {
        $config = $this->guards->get($guard);

        if (! $config->passwordResetEnabled()) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->ensure($config, [ThrottleKind::LoginIp], null, $data->context, ActivityType::PasswordReset);

        $pending = Models::oneTimeTokens()
            ->forPurpose($guard, OneTimeTokenPurpose::PasswordReset)
            ->where('token_hash', $this->hasher->link($guard, OneTimeTokenPurpose::PasswordReset->value, $data->token))
            ->usable(CarbonImmutable::now())
            ->first();

        if ($pending === null) {
            $this->fail($guard, $data);
        }

        $this->policy->execute($config, $data->password, null, $pending->email);

        try {
            $account = $this->consume->execute($guard, OneTimeTokenPurpose::PasswordReset, $data->token, $data->context)->account;
        } catch (InvalidOneTimeToken) {
            $this->fail($guard, $data);
        }

        PasswordWriter::write($account, $data->password);

        if (! $account->hasVerifiedEmail()) {
            $account->markEmailAsVerified();
        }

        if ($config->passwordResetUnlocks() && $account->isLocked()) {
            AccountState::write($account, [Columns::lockedUntil() => null, Columns::failedLoginCount() => 0]);
        }

        $this->invalidate->execute($config, $account, InvalidationReason::PasswordReset, null, $data->context);

        event(new PasswordReset($guard, $account));
        $this->notifications->send($config, NotificationType::PasswordChanged, $account, new NotificationData($guard));

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::PasswordReset,
            outcome: ActivityOutcome::Succeeded,
            context: $data->context,
            account: $account,
        ));

        if (! $config->loginAfterPasswordReset()) {
            return null;
        }

        return $this->completeFirstFactor->execute($config, $account, LoginMethod::PasswordReset, $data->context, [AuthMethodReference::Email]);
    }

    private function fail(string $guard, PasswordResetData $data): never
    {
        $config = $this->guards->get($guard);
        $this->throttle->hit($config, [ThrottleKind::LoginIp], null, $data->context->ipAddress);

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::PasswordReset,
            outcome: ActivityOutcome::FailedToken,
            context: $data->context,
        ));

        throw new InvalidOneTimeToken;
    }
}
