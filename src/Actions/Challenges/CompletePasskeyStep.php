<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

/**
 * Verifies a passkey second factor: the assertion must answer the ceremony this
 * challenge started, and the credential must be this account's. A failure counts an
 * attempt.
 */
final readonly class CompletePasskeyStep
{
    public function __construct(
        private FindActiveChallenge $findChallenge,
        private RecordChallengeFailure $recordFailure,
        private AdvanceChallenge $advance,
    ) {}

    public function execute(string $guard, ChallengeFactorData $data): LoginResult
    {
        $challenge = $this->findChallenge->execute($guard, $data->challengeToken, $data->context);
        $challenge->nextRequirement([ChallengeStep::SecondFactor, ChallengeStep::Passkey], FactorMethod::Passkey);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        $ceremony = $challenge->contextValue('passkey_ceremony');
        $assertion = $data->assertion;

        if ($assertion === null || ! is_string($ceremony) || ! ConstantTime::equals($ceremony, (string) $assertion->ceremonyId)) {
            $this->fail($challenge, $data);
        }

        try {
            Passkeys::authenticate($assertion, AuthenticationExpectation::owner(AccountModels::passkeys($account)));
        } catch (PasskeyException) {
            $this->fail($challenge, $data);
        }

        return $this->advance->execute($challenge->fresh() ?? $challenge, $data->challengeToken, FactorMethod::Passkey, [AuthMethodReference::Hwk], $data->context);
    }

    private function fail(LoginChallenge $challenge, ChallengeFactorData $data): never
    {
        throw ChallengeFactorFailed::withAttemptsLeft($this->recordFailure->execute($challenge, ActivityOutcome::FailedFactor, $data->context, FactorMethod::Passkey->value));
    }
}
