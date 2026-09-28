<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\VerifyOneTimeCode;
use RoundlyConsulting\Auth\Actions\Passwords\VerifyPassword;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationProof;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\Reauthenticated;
use RoundlyConsulting\Auth\Events\RecoveryCodeUsed;
use RoundlyConsulting\Auth\Exceptions\AccountLocked;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Exceptions\FactorNotAllowed;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Lockout;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use SensitiveParameter;

/**
 * "Sudo mode": the signed-in account re-proves itself, and its session (`sid`) counts as
 * recently authenticated for `reauthentication.timeout` — the marker records the method,
 * so a second factor enrolled later still demands a second-factor proof. An account with a second factor
 * must use it (password and email codes are refused) — a stolen session plus a leaked
 * password must not be able to disable the factor that protects the account.
 *
 * The TOTP and recovery-code methods share one check (two-factor reports which one
 * matched): the marker records the factor that actually matched, and a spent recovery
 * code is announced to the owner exactly as at login.
 */
final readonly class Reauthenticate
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private VerifyPassword $verifyPassword,
        private VerifyOneTimeCode $verifyCode,
        private ReauthenticationMarker $marker,
        private RecordLoginActivity $recordActivity,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, ReauthenticationData $data): CarbonImmutable
    {
        $config = $this->guards->get($guard);
        $sessionKey = $data->current->sessionKey();

        $this->throttle->attempt($config, [ThrottleKind::Reauthentication], $sessionKey, $data->context, ActivityType::Reauthentication);

        // The attempt stays counted only for a wrong proof; any other refusal gives it back.
        $wrong = false;
        $recoveryCodesLeft = null;

        try {
            if ($account->isLocked()) {
                throw AccountLocked::retryAfter(Lockout::secondsRemaining($account));
            }

            if (! in_array($data->method, ReauthenticationMethods::available($config, $account), true)) {
                throw new FactorNotAllowed;
            }

            try {
                $proven = $this->verify($config, $account, $data, $recoveryCodesLeft);
            } catch (InvalidCode $e) {
                $wrong = true;
                $this->fail($config, $account, $data);

                throw $e;
            }

            if ($proven === null) {
                $wrong = true;
                $this->fail($config, $account, $data);

                throw $data->method === ReauthenticationMethod::Password ? new InvalidCredentials : new InvalidCode;
            }
        } finally {
            if (! $wrong) {
                $this->throttle->release($config, [ThrottleKind::Reauthentication], $sessionKey, $data->context->ipAddress);
            }
        }

        $now = CarbonImmutable::now();
        $this->marker->put($guard, $sessionKey, new ReauthenticationProof($proven, $now), $config->reauthenticationTimeout());
        $this->throttle->clear($config, ThrottleKind::Reauthentication, $sessionKey, null);

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::Reauthentication,
            outcome: ActivityOutcome::Succeeded,
            context: $data->context,
            method: $proven->value,
            account: $account,
            sessionId: $data->current->sessionId,
        ));

        event(new Reauthenticated($guard, $account, $proven));

        if ($proven === ReauthenticationMethod::RecoveryCode) {
            event(new RecoveryCodeUsed($guard, $account, (int) $recoveryCodesLeft));

            $this->notifications->send($config, NotificationType::RecoveryCodeUsed, $account, new NotificationData(
                guard: $guard,
                replacements: ['remaining' => (int) $recoveryCodesLeft],
            ));
        }

        return $now->addSeconds($config->reauthenticationTimeout());
    }

    /**
     * The method that proved the account (null: the proof failed).
     *
     * @param-out int|null $recoveryCodesLeft
     *
     * @throws AuthException
     */
    private function verify(GuardConfig $guard, Account $account, ReauthenticationData $data, ?int &$recoveryCodesLeft): ?ReauthenticationMethod
    {
        $verified = match ($data->method) {
            ReauthenticationMethod::Password => $this->verifyPassword->execute($account, (string) $data->password),
            ReauthenticationMethod::Totp, ReauthenticationMethod::RecoveryCode => $this->verifyTwoFactor($account, (string) $data->code, $recoveryCodesLeft),
            ReauthenticationMethod::Passkey => $this->verifyPasskey($guard, $account, $data),
            ReauthenticationMethod::EmailOtp => $this->verifyCode->execute($guard->name(), OneTimeTokenPurpose::Reauthentication, (string) $account->accountEmail(), (string) $data->code, revealAttempts: true)->account->getAuthIdentifier() === $account->getAuthIdentifier(),
        };

        if (! $verified) {
            return null;
        }

        if ($data->method === ReauthenticationMethod::Totp || $data->method === ReauthenticationMethod::RecoveryCode) {
            return $recoveryCodesLeft === null ? ReauthenticationMethod::Totp : ReauthenticationMethod::RecoveryCode;
        }

        return $data->method;
    }

    /**
     * @param-out int|null $recoveryCodesLeft  set only when a recovery code matched
     */
    private function verifyTwoFactor(Account $account, #[SensitiveParameter] string $code, ?int &$recoveryCodesLeft): bool
    {
        try {
            $result = TwoFactor::for(AccountModels::twoFactor($account))->attempt($code);
        } catch (TwoFactorRateLimitedException $e) {
            throw TooManyAttempts::retryAfter($e->secondsUntilAvailable, $e);
        }

        if ($result->verified && $result->method === TwoFactorMethod::RecoveryCode) {
            $recoveryCodesLeft = $result->remainingRecoveryCodes;
        }

        return $result->verified;
    }

    private function verifyPasskey(GuardConfig $guard, Account $account, ReauthenticationData $data): bool
    {
        $ceremony = $this->marker->pullCeremony($guard->name(), $data->current->sessionKey());

        if ($data->assertion === null || $ceremony === null || ! ConstantTime::equals($ceremony, (string) $data->assertion->ceremonyId)) {
            return false;
        }

        try {
            Passkeys::for(AccountModels::passkeys($account))->authenticate($data->assertion);
        } catch (PasskeyException) {
            return false;
        }

        return true;
    }

    private function fail(GuardConfig $guard, Account $account, ReauthenticationData $data): void
    {
        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard->name(),
            type: ActivityType::Reauthentication,
            outcome: ActivityOutcome::FailedFactor,
            context: $data->context,
            method: $data->method->value,
            account: $account,
            sessionId: $data->current->sessionId,
        ));
    }
}
