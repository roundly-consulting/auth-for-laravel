<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\ChallengeContext;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use SensitiveParameter;

/**
 * Registration options for a forced passkey enrolment inside a challenge (idempotent:
 * calling again starts a new ceremony without counting an attempt). Once the account
 * has a passkey the step is stale and the challenge ends — a fresh login asks for the
 * passkey instead of letting whoever holds this challenge add one.
 */
final readonly class BeginPasskeyEnrolmentStep
{
    public function __construct(
        private GuardRegistry $guards,
        private FindActiveChallenge $findChallenge,
        private InvalidateChallenge $invalidateChallenge,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $challengeToken, SessionContext $context): CreationOptionsData
    {
        $config = $this->guards->get($guard);
        $challenge = $this->findChallenge->execute($guard, $challengeToken, $context);
        $challenge->nextRequirement([ChallengeStep::EnrolPasskey], FactorMethod::PasskeyEnrolment);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        if (! $config->allowsEnrolmentInChallenge() || ($config->enrolmentRequiresVerifiedEmail() && ! $account->hasVerifiedEmail())) {
            throw new EnrolmentRequired;
        }

        if (ReauthenticationMethods::hasPasskeys($config, $account)) {
            $this->invalidateChallenge->execute($challenge);
        }

        $options = Passkeys::for(AccountModels::passkeys($account))->registrationOptions();

        ChallengeContext::put($challenge, 'passkey_enrolment_ceremony', $options->ceremonyId);

        return $options;
    }
}
