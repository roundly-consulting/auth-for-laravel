<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\ChallengeContext;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use SensitiveParameter;

/**
 * Options for a passkey second factor: bound to the challenge's account (only its
 * credentials can answer) and remembered on the challenge, so an assertion for another
 * ceremony — another login, another user — cannot complete this one.
 */
final readonly class BeginPasskeyStep
{
    public function __construct(
        private GuardRegistry $guards,
        private FindActiveChallenge $findChallenge,
        private Throttle $throttle,
    ) {}

    public function execute(string $guard, #[SensitiveParameter] string $challengeToken, SessionContext $context): RequestOptionsData
    {
        $config = $this->guards->get($guard);
        $this->throttle->attempt($config, [ThrottleKind::LoginIp], null, $context, ActivityType::ChallengeStep);

        $challenge = $this->findChallenge->execute($guard, $challengeToken, $context);
        $challenge->nextRequirement([ChallengeStep::SecondFactor, ChallengeStep::Passkey], FactorMethod::Passkey);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        $options = Passkeys::authenticationOptions(AccountModels::passkeys($account));

        ChallengeContext::put($challenge, 'passkey_ceremony', $options->ceremonyId);

        return $options;
    }
}
