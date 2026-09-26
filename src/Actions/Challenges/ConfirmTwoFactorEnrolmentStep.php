<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\TwoFactorEnabled;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorNotPendingException;

/**
 * Confirms the forced TOTP enrolment. Possession was just proven, so this also
 * satisfies the login's second factor (amr `otp`). The account's pre-existing sessions
 * die with the 2FA change — but not this challenge, whose token-version snapshot moves
 * with it.
 */
final readonly class ConfirmTwoFactorEnrolmentStep
{
    public function __construct(
        private GuardRegistry $guards,
        private FindActiveChallenge $findChallenge,
        private RecordChallengeFailure $recordFailure,
        private AdvanceChallenge $advance,
        private ConfirmEnrolment $confirmEnrolment,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, ChallengeFactorData $data): LoginResult
    {
        $config = $this->guards->get($guard);
        $challenge = $this->findChallenge->execute($guard, $data->challengeToken, $data->context);
        $challenge->nextRequirement([ChallengeStep::EnrolTwoFactor], FactorMethod::TotpEnrolment);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        try {
            $this->confirmEnrolment->execute(AccountModels::twoFactor($account), (string) $data->code);
        } catch (InvalidTwoFactorCodeException $e) {
            throw ChallengeFactorFailed::withAttemptsLeft($this->recordFailure->execute($challenge, ActivityOutcome::FailedFactor, $data->context, FactorMethod::TotpEnrolment->value), $e);
        } catch (TwoFactorNotPendingException $e) {
            throw new ChallengeInvalid($e);
        }

        event(new TwoFactorEnabled($guard, $account));
        $this->notifications->send($config, NotificationType::TwoFactorEnabled, $account, new NotificationData($guard));

        $this->invalidate->execute($config, $account, InvalidationReason::TwoFactorChanged, null, $data->context, (int) $challenge->getKey());

        return $this->advance->execute($challenge, $data->challengeToken, FactorMethod::TotpEnrolment, [AuthMethodReference::Otp], $data->context, $account->tokenVersion());
    }
}
