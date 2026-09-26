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
use RoundlyConsulting\Auth\Events\PasskeyAdded;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

/**
 * Registers the passkey of a forced enrolment. The new credential also satisfies this
 * login's factor (amr `hwk`); `invalidation.passkey_changed` applies to the account's
 * other sessions, never to this challenge.
 */
final readonly class CompletePasskeyEnrolmentStep
{
    public function __construct(
        private GuardRegistry $guards,
        private FindActiveChallenge $findChallenge,
        private RecordChallengeFailure $recordFailure,
        private AdvanceChallenge $advance,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, ChallengeFactorData $data): LoginResult
    {
        $config = $this->guards->get($guard);
        $challenge = $this->findChallenge->execute($guard, $data->challengeToken, $data->context);
        $challenge->nextRequirement([ChallengeStep::EnrolPasskey], FactorMethod::PasskeyEnrolment);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        $ceremony = $challenge->contextValue('passkey_enrolment_ceremony');
        $attestation = $data->attestation;

        if ($attestation === null || ! is_string($ceremony) || ! ConstantTime::equals($ceremony, (string) $attestation->ceremonyId)) {
            $this->fail($challenge, $data);
        }

        try {
            $passkey = Passkeys::register(AccountModels::passkeys($account), $attestation, $data->passkeyName);
        } catch (PasskeyException) {
            $this->fail($challenge, $data);
        }

        event(new PasskeyAdded($guard, $account, (int) $passkey->getKey()));
        $this->notifications->send($config, NotificationType::PasskeyAdded, $account, new NotificationData($guard));

        $this->invalidate->execute($config, $account, InvalidationReason::PasskeyChanged, null, $data->context, (int) $challenge->getKey());

        return $this->advance->execute($challenge->fresh() ?? $challenge, $data->challengeToken, FactorMethod::PasskeyEnrolment, [AuthMethodReference::Hwk], $data->context, $account->tokenVersion());
    }

    private function fail(LoginChallenge $challenge, ChallengeFactorData $data): never
    {
        throw ChallengeFactorFailed::withAttemptsLeft($this->recordFailure->execute($challenge, ActivityOutcome::FailedFactor, $data->context, FactorMethod::PasskeyEnrolment->value));
    }
}
