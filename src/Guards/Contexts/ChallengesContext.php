<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Auth\Actions\Challenges\BeginPasskeyEnrolmentStep;
use RoundlyConsulting\Auth\Actions\Challenges\BeginPasskeyStep;
use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyEnrolmentStep;
use RoundlyConsulting\Auth\Actions\Challenges\CompletePasskeyStep;
use RoundlyConsulting\Auth\Actions\Challenges\CompleteTwoFactorStep;
use RoundlyConsulting\Auth\Actions\Challenges\ConfirmTwoFactorEnrolmentStep;
use RoundlyConsulting\Auth\Actions\Challenges\StartTwoFactorEnrolmentStep;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TwoFactorSetupData;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use SensitiveParameter;

/**
 * The login challenges of one guard — `Authentication::challenges()` /
 * `Authentication::guard('clients')->challenges()`: continue a `LoginResult` that
 * `requiresChallenge()`. A challenge token of another guard is `ChallengeInvalid` here.
 */
final readonly class ChallengesContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * Complete the next step with a TOTP / recovery code, an enrolment confirmation, a
     * passkey assertion or a passkey registration (by `$data->method`).
     */
    public function complete(ChallengeFactorData $data): LoginResult
    {
        $action = match ($data->method) {
            FactorMethod::Totp, FactorMethod::RecoveryCode => CompleteTwoFactorStep::class,
            FactorMethod::TotpEnrolment => ConfirmTwoFactorEnrolmentStep::class,
            FactorMethod::Passkey => CompletePasskeyStep::class,
            FactorMethod::PasskeyEnrolment => CompletePasskeyEnrolmentStep::class,
        };

        return $this->make($action)->execute($this->guardName(), $data);
    }

    /**
     * Request options for a passkey second factor, bound to the challenge.
     */
    public function passkeyOptions(#[SensitiveParameter] string $challengeToken, SessionContext $context): RequestOptionsData
    {
        return $this->make(BeginPasskeyStep::class)->execute($this->guardName(), $challengeToken, $context);
    }

    /**
     * Creation options for a forced passkey enrolment, bound to the challenge.
     */
    public function passkeyEnrolmentOptions(#[SensitiveParameter] string $challengeToken, SessionContext $context): CreationOptionsData
    {
        return $this->make(BeginPasskeyEnrolmentStep::class)->execute($this->guardName(), $challengeToken, $context);
    }

    /**
     * Start the forced TOTP enrolment of a challenge; confirm it with `complete()` and
     * `FactorMethod::TotpEnrolment`.
     */
    public function startTwoFactorEnrolment(#[SensitiveParameter] string $challengeToken, SessionContext $context): TwoFactorSetupData
    {
        return $this->make(StartTwoFactorEnrolmentStep::class)->execute($this->guardName(), $challengeToken, $context);
    }
}
