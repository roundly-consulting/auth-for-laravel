<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\RecoveryCodeUsed;
use RoundlyConsulting\Auth\Exceptions\ChallengeFactorFailed;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

/**
 * A TOTP code — or a recovery code, on the same endpoint: two-factor-for-laravel reports
 * which one matched (and runs its atomic replay guard and per-user limiter). A used
 * recovery code is announced to the owner with the number left.
 */
final readonly class CompleteTwoFactorStep
{
    public function __construct(
        private GuardRegistry $guards,
        private FindActiveChallenge $findChallenge,
        private RecordChallengeFailure $recordFailure,
        private AdvanceChallenge $advance,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, ChallengeFactorData $data): LoginResult
    {
        $config = $this->guards->get($guard);
        $challenge = $this->findChallenge->execute($guard, $data->challengeToken, $data->context);

        $challenge->nextRequirement([ChallengeStep::SecondFactor], $data->method === FactorMethod::RecoveryCode ? FactorMethod::RecoveryCode : FactorMethod::Totp);

        $account = $challenge->account;

        if (! $account instanceof Account) {
            throw new ChallengeInvalid;
        }

        try {
            $result = TwoFactor::attempt(AccountModels::twoFactor($account), (string) $data->code);
        } catch (TwoFactorRateLimitedException $e) {
            throw TooManyAttempts::retryAfter($e->secondsUntilAvailable, $e);
        }

        if (! $result->verified) {
            $left = $this->recordFailure->execute($challenge, $result->replayed ? ActivityOutcome::Replayed : ActivityOutcome::FailedFactor, $data->context, $data->method->value);

            throw ChallengeFactorFailed::withAttemptsLeft($left);
        }

        $method = $result->method === TwoFactorMethod::RecoveryCode ? FactorMethod::RecoveryCode : FactorMethod::Totp;

        if ($method === FactorMethod::RecoveryCode) {
            event(new RecoveryCodeUsed($guard, $account, $result->remainingRecoveryCodes));

            $this->notifications->send($config, NotificationType::RecoveryCodeUsed, $account, new NotificationData(
                guard: $guard,
                replacements: ['remaining' => $result->remainingRecoveryCodes],
            ));
        }

        return $this->advance->execute($challenge, $data->challengeToken, $method, [AuthMethodReference::Otp], $data->context);
    }
}
