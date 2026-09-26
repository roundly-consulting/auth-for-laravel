<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\OneTimeTokens\VerifyOneTimeCode;
use RoundlyConsulting\Auth\Actions\Passwords\VerifyPassword;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\Reauthenticated;
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
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use SensitiveParameter;

/**
 * "Sudo mode": the signed-in account re-proves itself, and its session (`sid`) counts as
 * recently authenticated for `reauthentication.timeout`. An account with a second factor
 * must use it (password and email codes are refused) — a stolen session plus a leaked
 * password must not be able to disable the factor that protects the account.
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
    ) {}

    public function execute(string $guard, Account $account, ReauthenticationData $data): CarbonImmutable
    {
        $config = $this->guards->get($guard);
        $sessionKey = $data->current->sessionKey();

        $this->throttle->ensure($config, [ThrottleKind::Reauthentication], $sessionKey, $data->context, ActivityType::Reauthentication);

        if ($account->isLocked()) {
            throw AccountLocked::retryAfter(Lockout::secondsRemaining($account));
        }

        if (! in_array($data->method, ReauthenticationMethods::available($config, $account), true)) {
            throw new FactorNotAllowed;
        }

        try {
            $verified = $this->verify($config, $account, $data);
        } catch (InvalidCode $e) {
            $this->fail($config, $account, $data, $sessionKey);

            throw $e;
        }

        if (! $verified) {
            $this->fail($config, $account, $data, $sessionKey);

            throw $data->method === ReauthenticationMethod::Password ? new InvalidCredentials : new InvalidCode;
        }

        $now = CarbonImmutable::now();
        $this->marker->put($guard, $sessionKey, $now, $config->reauthenticationTimeout());
        $this->throttle->clear($config, ThrottleKind::Reauthentication, $sessionKey, null);

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::Reauthentication,
            outcome: ActivityOutcome::Succeeded,
            context: $data->context,
            method: $data->method->value,
            account: $account,
            sessionId: $data->current->sessionId,
        ));

        event(new Reauthenticated($guard, $account, $data->method));

        return $now->addSeconds($config->reauthenticationTimeout());
    }

    /**
     * @throws AuthException
     */
    private function verify(GuardConfig $guard, Account $account, ReauthenticationData $data): bool
    {
        return match ($data->method) {
            ReauthenticationMethod::Password => $this->verifyPassword->execute($account, (string) $data->password),
            ReauthenticationMethod::Totp, ReauthenticationMethod::RecoveryCode => $this->verifyTwoFactor($account, (string) $data->code),
            ReauthenticationMethod::Passkey => $this->verifyPasskey($guard, $account, $data),
            ReauthenticationMethod::EmailOtp => $this->verifyCode->execute($guard->name(), OneTimeTokenPurpose::Reauthentication, (string) $account->accountEmail(), (string) $data->code, revealAttempts: true)->account->getAuthIdentifier() === $account->getAuthIdentifier(),
        };
    }

    private function verifyTwoFactor(Account $account, #[SensitiveParameter] string $code): bool
    {
        try {
            return TwoFactor::attempt(AccountModels::twoFactor($account), $code)->verified;
        } catch (TwoFactorRateLimitedException $e) {
            throw TooManyAttempts::retryAfter($e->secondsUntilAvailable, $e);
        }
    }

    private function verifyPasskey(GuardConfig $guard, Account $account, ReauthenticationData $data): bool
    {
        $ceremony = $this->marker->pullCeremony($guard->name(), $data->current->sessionKey());

        if ($data->assertion === null || $ceremony === null || ! ConstantTime::equals($ceremony, (string) $data->assertion->ceremonyId)) {
            return false;
        }

        try {
            Passkeys::authenticate($data->assertion, AuthenticationExpectation::owner(AccountModels::passkeys($account)));
        } catch (PasskeyException) {
            return false;
        }

        return true;
    }

    private function fail(GuardConfig $guard, Account $account, ReauthenticationData $data, string $sessionKey): void
    {
        $this->throttle->hit($guard, [ThrottleKind::Reauthentication], $sessionKey, $data->context->ipAddress);

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
