<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorSetupData;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Exceptions\TwoFactorAlreadyEnabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\TwoFactorEnrolments;
use SensitiveParameter;

/**
 * Starts the forced TOTP enrolment of a challenge. Idempotent per challenge: calling it
 * again re-issues the setup (the unconfirmed secret is replaced) without counting an
 * attempt.
 */
final readonly class StartTwoFactorEnrolmentStep
{
    public function __construct(
        private GuardRegistry $guards,
        private FindActiveChallenge $findChallenge,
        private TwoFactorEnrolments $enrolments,
        private InvalidateChallenge $invalidateChallenge,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $challengeToken, SessionContext $context): TwoFactorSetupData
    {
        $config = $this->guards->get($guard);
        $challenge = $this->findChallenge->execute($guard, $challengeToken, $context);
        $challenge->nextRequirement([ChallengeStep::EnrolTwoFactor], FactorMethod::TotpEnrolment);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        if (! $config->allowsEnrolmentInChallenge() || ($config->enrolmentRequiresVerifiedEmail() && ! $account->hasVerifiedEmail())) {
            throw new EnrolmentRequired;
        }

        try {
            return $this->enrolments->start($config, $account);
        } catch (TwoFactorAlreadyEnabled) {
            // Enabled elsewhere meanwhile: this step no longer fits the account.
            $this->invalidateChallenge->execute($challenge);
        }
    }
}
